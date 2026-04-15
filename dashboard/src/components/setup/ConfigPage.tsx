"use client";

import React, { useState, useEffect, useCallback } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import {
  Cpu, MessageSquare, ShieldAlert, Check, Save, RotateCcw, Wifi, Loader2,
  CheckCircle2, Eye, Bell, ShieldCheck, Zap, AlertTriangle, Globe, Shield,
  Plus, Trash2, Send, Bot, ArrowRight, Database, Key, Radio, Mail,
  Clock, Download, Play, XCircle, Cloud, ChevronDown, ChevronRight, X, Settings, RefreshCw, HelpCircle, Activity,
} from "lucide-react";

import RemediationTab from "./RemediationTab";

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
import { ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { NeuCard as ChromeInsetCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";

const PERM_LEVELS = [
  { id: "READ_ONLY", icon: Eye, labelKey: "observation", descKey: "observationOnly", color: "#5a6a8a" },
  { id: "ALERT_ONLY", icon: Bell, labelKey: "alertsOnly", descKey: "alertsNoAction", color: "var(--tc-green)", recommended: true },
  { id: "REMEDIATE_WITH_APPROVAL", icon: ShieldCheck, labelKey: "remediationSupervised", descKey: "remediationWithApproval", color: "var(--tc-amber)" },
  { id: "FULL_AUTO", icon: Zap, labelKey: "autoMode", descKey: "fullAutoDesc", color: "var(--tc-red)", warning: true },
];

interface ConfigPageProps { onResetWizard: () => void; }

export default function ConfigPage({ onResetWizard }: ConfigPageProps) {
  const locale = useLocale();
  const [activeTab, setActiveTab] = useState(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      return params.get("configTab") || "general";
    }
    return "general";
  });
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  const [llm, setLlm] = useState({ backend: "ollama", url: "http://127.0.0.1:11434", model: "", apiKey: "", connected: false, testing: false, models: [] as string[] });
  const [conversational, setConversational] = useState({ source: "disabled" as "disabled" | "local" | "cloud", localModel: "gemma4:26b", cloudBackend: "anthropic", cloudModel: "", cloudApiKey: "", anonymize: true });
  const [forensic, setForensic] = useState({ model: "threatclaw-l2", url: "" });
  const [instruct, setInstruct] = useState({ model: "threatclaw-l3", url: "" });
  const [cloud, setCloud] = useState({ enabled: false, backend: "anthropic", model: "", apiKey: "", escalation: "anonymized" });
  const [shiftReport, setShiftReport] = useState({ enabled: false, interval_minutes: 240, notify_threshold: 20, daily_summary_hour: 8 });
  const [channels, setChannels] = useState<Record<string, { enabled: boolean; [k: string]: string | boolean }>>({
    slack: { enabled: false, botToken: "", signingSecret: "" },
    telegram: { enabled: false, botToken: "", botUsername: "", chatId: "" },
    discord: { enabled: false, botToken: "", publicKey: "" },
    whatsapp: { enabled: false, accessToken: "", phoneNumberId: "" },
    signal: { enabled: false, httpUrl: "http://localhost:8080", account: "" },
    email: { enabled: false, host: "", port: "587", from: "", to: "" },
    mattermost: { enabled: false, webhookUrl: "" },
    ntfy: { enabled: false, server: "https://ntfy.sh", topic: "" },
    gotify: { enabled: false, url: "", appToken: "" },
    olvid: { enabled: false, daemonUrl: "http://localhost:50051", clientKey: "", discussionId: "" },
  });
  const [permLevel, setPermLevel] = useState("ALERT_ONLY");
  const [general, setGeneral] = useState({ instanceName: "threatclaw-dev", language: (typeof window !== "undefined" && localStorage.getItem("tc-language")) || "fr", nvdApiKey: "" });

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
        if (cfg.conversational) setConversational(p => ({ ...p, ...cfg.conversational }));
        if (cfg.forensic) setForensic(p => ({ ...p, ...cfg.forensic }));
        if (cfg.instruct) setInstruct(p => ({ ...p, ...cfg.instruct }));
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
        if (cfg.shift_report) setShiftReport(p => ({ ...p, ...cfg.shift_report }));
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
      conversational,
      forensic: { model: forensic.model, url: forensic.url || llm.url },
      instruct: { model: instruct.model, url: instruct.url || llm.url },
      channels,
      permissions: permLevel,
      general,
    };
    if (cloud.enabled && cloud.apiKey) {
      config.cloud = { backend: cloud.backend, model: cloud.model, apiKey: cloud.apiKey, escalation: cloud.escalation };
    }
    config.shift_report = shiftReport;
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
    } catch { return { ok: false, error: tr("connectionFailed", locale) }; }
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
    width: "100%", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)",
    padding: "10px 14px", fontSize: "13px", color: "var(--tc-text)", fontFamily: "inherit",
    background: "var(--tc-input)", outline: "none",
    boxShadow: "inset 0 2px 4px rgba(0,0,0,0.3), inset 0 0 0 1px var(--tc-input)",
    transition: "border-color 0.2s ease",
  };

  const labelStyle: React.CSSProperties = {
    fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)",
    textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "6px",
  };

  const tabs = [
    { id: "general", label: tr("general", locale), icon: Globe },
    { id: "company", label: tr("company", locale), icon: Shield },
    { id: "llm", label: tr("threatclawAi", locale), icon: Cpu },
    { id: "channels", label: tr("channels", locale), icon: MessageSquare },
    { id: "security", label: tr("security", locale), icon: ShieldAlert },
    { id: "remediation", label: locale === "fr" ? "Remédiation" : "Remediation", icon: Shield },
    { id: "agent", label: tr("agentEngine", locale), icon: Activity },
    { id: "notifications", label: tr("notifications", locale), icon: Bell },
    { id: "retention", label: tr("retention", locale), icon: Clock },
    { id: "anonymizer", label: tr("anonymizer", locale), icon: Shield },
    { id: "backup", label: tr("backupUpdate", locale), icon: Download },
    { id: "logs", label: tr("logs", locale), icon: Eye },
    { id: "sources", label: locale === "fr" ? "Sources de logs" : "Log Sources", icon: Radio },
  ];

  const channelDefs = [
    { key: "slack", label: "Slack", icon: <SlackIcon />, fields: [{ id: "botToken", label: "Bot Token (xoxb-...)", secret: true }, { id: "signingSecret", label: "Signing Secret", secret: true }] },
    { key: "telegram", label: "Telegram", icon: <TelegramIcon />, fields: [{ id: "botToken", label: "Bot Token", secret: true }, { id: "botUsername", labelKey: "botUsername", secret: false }, { id: "chatId", labelKey: "chatIdNotif", secret: false }] },
    { key: "discord", label: "Discord", icon: <DiscordIcon />, fields: [{ id: "botToken", label: "Bot Token", secret: true }, { id: "publicKey", label: "Public Key", secret: false }] },
    { key: "whatsapp", label: "WhatsApp", icon: <MessageSquare size={18} color="#30a050" />, fields: [{ id: "accessToken", label: "Access Token", secret: true }, { id: "phoneNumberId", label: "Phone Number ID", secret: false }] },
    { key: "signal", label: "Signal", icon: <Shield size={18} color="#3080d0" />, fields: [{ id: "httpUrl", labelKey: "signalUrl", secret: false }, { id: "account", labelKey: "phoneNumber", secret: false }] },
    { key: "email", label: "Email", icon: <Mail size={18} color="var(--tc-text-sec)" />, fields: [{ id: "host", label: "SMTP", secret: false }, { id: "port", label: "Port", secret: false }, { id: "from", labelKey: "from", secret: false }, { id: "to", labelKey: "toField", secret: false }] },
    { key: "mattermost", label: "Mattermost (on-premise)", icon: <MessageSquare size={18} color="#0058cc" />, fields: [{ id: "webhookUrl", label: "Incoming Webhook URL", secret: false }] },
    { key: "ntfy", label: "Ntfy (on-premise)", icon: <Bell size={18} color="#30a050" />, fields: [{ id: "server", labelKey: "ntfyServer", secret: false }, { id: "topic", label: "Topic", secret: false }] },
    { key: "gotify", label: "Gotify (notifs uniquement)", icon: <Bell size={18} color="#d09020" />, fields: [{ id: "url", labelKey: "gotifyUrl", secret: false }, { id: "appToken", label: "App Token", secret: true }] },
    { key: "olvid", label: "Olvid (certifié ANSSI)", icon: <Shield size={18} color="#1a56db" />, fields: [{ id: "daemonUrl", label: "URL daemon gRPC", secret: false }, { id: "clientKey", label: "Client Key", secret: true }, { id: "discussionId", label: "Discussion ID (alertes)", secret: false }] },
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
              padding: "8px 16px", borderRadius: "var(--tc-radius-md)", border: "none",
              fontSize: "12px", fontWeight: 600, fontFamily: "inherit",
              cursor: "pointer", transition: "all 0.2s ease",
              background: active ? "rgba(208,48,32,0.08)" : "var(--tc-surface-alt)",
              color: active ? "#d03020" : "var(--tc-text-sec)",
              borderColor: active ? "rgba(208,48,32,0.15)" : "var(--tc-border)",
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
              <Globe size={18} color="#d03020" /> {tr("configGeneral", locale)}
            </ChromeEmbossedText>
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div>
                <div style={labelStyle}>{tr("instanceName", locale)}</div>
                <input style={inputStyle} value={general.instanceName} onChange={e => setGeneral(p => ({ ...p, instanceName: e.target.value }))} />
              </div>
              <div>
                <div style={labelStyle}>{tr("language", locale)}</div>
                <GlassSelect value={general.language} onChange={v => { setGeneral(p => ({ ...p, language: v })); localStorage.setItem("tc-language", v); window.dispatchEvent(new Event("tc-locale-change")); }} options={[
                  { value: "fr", label: tr("french", locale) }, { value: "en", label: tr("english", locale) },
                ]} />
              </div>
              {/* NVD API key moved to Config > Enrichissement */}
            </div>
          </ChromeInsetCard>
        )}

        {/* ═══ LLM — 3 niveaux ═══ */}
        {activeTab === "company" && (<CompanyTab />)}

        {activeTab === "llm" && (<>
          <LlmTab
            llm={llm} setLlm={setLlm} conversational={conversational} setConversational={setConversational}
            forensic={forensic} setForensic={setForensic}
            instruct={instruct} setInstruct={setInstruct}
            cloud={cloud} setCloud={setCloud} llmModels={llmModels} setLlmModels={setLlmModels}
            testOllama={testOllama} inputStyle={inputStyle} labelStyle={labelStyle}
          />
          <ChromeInsetCard style={{ marginTop: "16px" }}>
            <h3 style={{ marginBottom: "4px" }}>{tr("shiftReportTitle", locale)}</h3>
            <p style={{ fontSize: "13px", opacity: 0.7, marginBottom: "12px" }}>{tr("shiftReportDesc", locale)}</p>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
              <input type="checkbox" className="tc-toggle" checked={shiftReport.enabled} onChange={e => setShiftReport(p => ({ ...p, enabled: e.target.checked }))} />
              <span style={{ fontSize: "14px" }}>{tr("shiftReportEnabled", locale)}</span>
            </div>
            {shiftReport.enabled && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <label style={labelStyle}>{tr("shiftReportInterval", locale)}</label>
                  <input type="number" min={60} max={1440} step={60} value={shiftReport.interval_minutes} onChange={e => setShiftReport(p => ({ ...p, interval_minutes: parseInt(e.target.value) || 240 }))} style={inputStyle} />
                </div>
                <div>
                  <label style={labelStyle}>{tr("shiftReportThreshold", locale)}</label>
                  <input type="number" min={0} max={100} value={shiftReport.notify_threshold} onChange={e => setShiftReport(p => ({ ...p, notify_threshold: parseInt(e.target.value) || 20 }))} style={inputStyle} />
                  <span style={{ fontSize: "11px", opacity: 0.6 }}>{tr("shiftReportThresholdHelp", locale)}</span>
                </div>
                <div>
                  <label style={labelStyle}>{tr("shiftReportDailyHour", locale)}</label>
                  <input type="number" min={0} max={255} value={shiftReport.daily_summary_hour} onChange={e => setShiftReport(p => ({ ...p, daily_summary_hour: parseInt(e.target.value) || 8 }))} style={inputStyle} />
                  <span style={{ fontSize: "11px", opacity: 0.6 }}>{tr("shiftReportDailyHourHelp", locale)}</span>
                </div>
              </div>
            )}
          </ChromeInsetCard>
        </>)}

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
                  <input type="checkbox" className="tc-toggle" checked={isEnabled}
                    onChange={() => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], enabled: !isEnabled } }))} />
                </div>

                {isEnabled && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "16px" }}>
                    {ch.fields.map(f => (
                      <div key={f.id}>
                        <div style={labelStyle}>{(f as any).labelKey ? tr((f as any).labelKey, locale) : f.label}</div>
                        <input style={inputStyle}
                          type={f.secret ? "password" : "text"}
                          value={(chState[f.id] as string) || ""}
                          onChange={e => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], [f.id]: e.target.value } }))} />
                      </div>
                    ))}

                    {/* Telegram special: status + test message */}
                    {ch.key === "telegram" && (
                      <div style={{ borderTop: "1px solid var(--tc-border-light)", paddingTop: "16px" }}>
                        {/* Bot status */}
                        {telegramStatus && (
                          <div style={{
                            display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px",
                            padding: "10px 14px", borderRadius: "var(--tc-radius-md)",
                            background: telegramStatus.ok ? "rgba(48,160,80,0.06)" : "rgba(208,48,32,0.06)",
                            border: `1px solid ${telegramStatus.ok ? "rgba(48,160,80,0.15)" : "rgba(208,48,32,0.15)"}`,
                          }}>
                            <Bot size={16} color={telegramStatus.ok ? "#30a050" : "#d03020"} />
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: "13px", fontWeight: 600, color: telegramStatus.ok ? "#30a050" : "#d03020" }}>
                                {telegramStatus.ok ? `@${telegramStatus.username} — ${tr("connected", locale)}` : tr("notConnected", locale)}
                              </div>
                              {telegramStatus.error && <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{String(telegramStatus.error)}</div>}
                            </div>
                            <ChromeButton onClick={checkTelegram} variant="glass">
                              <RotateCcw size={12} />
                            </ChromeButton>
                          </div>
                        )}

                        {/* Send test message */}
                        <div style={labelStyle}>{tr("sendTestMessage", locale)}</div>
                        <div style={{ display: "flex", gap: "8px" }}>
                          <input style={{ ...inputStyle, flex: 1 }} value={telegramTestMsg}
                            onChange={e => setTelegramTestMsg(e.target.value)}
                            placeholder={tr("telegramPlaceholder", locale)}
                            onKeyDown={e => e.key === "Enter" && sendTelegramTest()} />
                          <ChromeButton onClick={sendTelegramTest} disabled={telegramSending || !telegramTestMsg} variant="primary">
                            {telegramSending ? <Loader2 size={14} className="animate-spin" /> : telegramSent ? <CheckCircle2 size={14} /> : <Send size={14} />}
                            {telegramSent ? tr("sent", locale) : tr("send", locale)}
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
              <ShieldAlert size={18} color="#d03020" /> {tr("securityLevel", locale)}
            </ChromeEmbossedText>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {PERM_LEVELS.map(level => {
                const LIcon = level.icon;
                const sel = permLevel === level.id;
                return (
                  <button key={level.id} onClick={() => setPermLevel(level.id)} style={{
                    display: "flex", alignItems: "center", gap: "14px",
                    background: sel ? "rgba(208,48,32,0.06)" : "var(--tc-surface-alt)",
                    border: sel ? "1px solid rgba(208,48,32,0.15)" : "1px solid var(--tc-input)",
                    borderRadius: "var(--tc-radius-card)", cursor: "pointer", padding: "14px 16px",
                    textAlign: "left", transition: "all 0.2s ease", fontFamily: "inherit",
                    color: "inherit",
                  }}>
                    <LIcon size={20} color={level.color} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", display: "flex", alignItems: "center", gap: "8px" }}>
                        {tr(level.labelKey, locale)}
                        {level.recommended && <span style={{ fontSize: "9px", color: "var(--tc-green)", fontWeight: 600, padding: "2px 6px", background: "var(--tc-green-soft)", borderRadius: "4px" }}>{tr("recommended", locale)}</span>}
                        {level.warning && <span style={{ fontSize: "9px", color: "var(--tc-red)", fontWeight: 600, padding: "2px 6px", background: "var(--tc-red-soft)", borderRadius: "4px", display: "inline-flex", alignItems: "center", gap: "3px" }}><AlertTriangle size={9} />{tr("advanced", locale)}</span>}
                      </div>
                      <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{tr(level.descKey, locale)}</div>
                    </div>
                    {sel && <Check size={18} color="#d03020" />}
                  </button>
                );
              })}
            </div>
          </ChromeInsetCard>
        )}

        {/* ═══ AGENT & MOTEUR ═══ */}
        {activeTab === "agent" && (
          <ChromeInsetCard>
            <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "12px" }}>ThreatClaw Engine</ChromeEmbossedText>
            <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "16px" }}>
              {tr("engineDesc", locale)}
            </p>
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              <ChromeButton onClick={() => window.location.href = "/agent"} variant="glass">
                <Activity size={14} /> {tr("openAgentPage", locale)}
              </ChromeButton>
            </div>
          </ChromeInsetCard>
        )}

        {/* ═══ NOTIFICATIONS ═══ */}
        {activeTab === "notifications" && (
          <NotificationsTab inputStyle={inputStyle} labelStyle={labelStyle} />
        )}

        {/* ═══ ENRICHMENT ═══ */}
        {activeTab === "retention" && (
          <RetentionTab />
        )}

        {/* ═══ ANONYMIZER ═══ */}
        {activeTab === "anonymizer" && (
          <AnonymizerSection inputStyle={inputStyle} labelStyle={labelStyle} />
        )}

        {activeTab === "remediation" && (<RemediationTab />)}
        {activeTab === "backup" && (<BackupTab />)}
        {activeTab === "logs" && (<LiveLogsTab />)}
        {activeTab === "sources" && (<LogSourcesTab />)}
      </div>

      {/* Actions bar */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "16px 20px", borderRadius: "14px",
        background: "rgba(18,18,26,0.5)", border: "1px solid var(--tc-border-light)",
        position: "sticky", bottom: "20px",
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      }}>
        <ChromeButton onClick={onResetWizard} variant="glass">
          <RotateCcw size={14} /> {tr("restartWizard", locale)}
        </ChromeButton>
        <ChromeButton onClick={handleSave} disabled={saving} variant="primary" style={{ minWidth: "220px" }}>
          {saving ? <Loader2 size={14} className="animate-spin" /> : saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
          {saved ? tr("save", locale) + " ✓" : tr("save", locale)}
        </ChromeButton>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════
// LLM TAB — 4-level AI architecture
// ═══════════════════════════════════════

interface LlmTabProps {
  llm: { backend: string; url: string; model: string; apiKey: string; connected: boolean; testing: boolean; models: string[] };
  setLlm: React.Dispatch<React.SetStateAction<LlmTabProps["llm"]>>;
  conversational: { source: "disabled" | "local" | "cloud"; localModel: string; cloudBackend: string; cloudModel: string; cloudApiKey: string; anonymize: boolean };
  setConversational: React.Dispatch<React.SetStateAction<LlmTabProps["conversational"]>>;
  forensic: { model: string; url: string };
  setForensic: React.Dispatch<React.SetStateAction<LlmTabProps["forensic"]>>;
  instruct: { model: string; url: string };
  setInstruct: React.Dispatch<React.SetStateAction<LlmTabProps["instruct"]>>;
  cloud: { enabled: boolean; backend: string; model: string; apiKey: string; escalation: string };
  setCloud: React.Dispatch<React.SetStateAction<LlmTabProps["cloud"]>>;
  llmModels: { name: string; size: string }[];
  setLlmModels: React.Dispatch<React.SetStateAction<LlmTabProps["llmModels"]>>;
  testOllama: () => Promise<void>;
  inputStyle: React.CSSProperties;
  labelStyle: React.CSSProperties;
}

// Custom styled select matching glass design
function GlassSelect({ value, onChange, options, placeholder }: {
  value: string; onChange: (v: string) => void;
  options: { value: string; label: string; detail?: string }[];
  placeholder?: string;
}) {
  return (
    <div style={{ position: "relative" }}>
      <select value={value} onChange={e => onChange(e.target.value)} style={{
        width: "100%", appearance: "none", WebkitAppearance: "none",
        background: "var(--tc-input)", border: "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-md)", padding: "12px 36px 12px 14px", fontSize: "13px",
        color: value ? "var(--tc-text)" : "var(--tc-text-muted)", fontFamily: "inherit", cursor: "pointer",
        outline: "none", transition: "border-color 0.2s",
        boxShadow: "inset 0 2px 4px rgba(0,0,0,0.3)",
      }}>
        {placeholder && <option value="">{placeholder}</option>}
        {options.map(o => <option key={o.value} value={o.value}>{o.label}{o.detail ? ` — ${o.detail}` : ""}</option>)}
      </select>
      <ChevronDown size={14} style={{ position: "absolute", right: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--tc-text-muted)", pointerEvents: "none" }} />
    </div>
  );
}

// ── Model download status + pull button ──
function ModelDownloadStatus({ model, ollamaUrl }: { model: string; ollamaUrl: string }) {
  const locale = useLocale();
  const [status, setStatus] = useState<"checking" | "ready" | "not_found" | "downloading" | "error">("checking");
  const [elapsed, setElapsed] = useState(0);

  // Check if model exists
  useEffect(() => {
    fetch("/api/ollama")
      .then(r => r.json())
      .then(d => {
        const models = (d.models || []).map((m: { name: string }) => m.name);
        const found = models.some((n: string) => n === model || n === model + ":latest");
        setStatus(found ? "ready" : "not_found");
      })
      .catch(() => setStatus("error"));
  }, [model]);

  const startDownload = () => {
    setStatus("downloading");
    setElapsed(0);
    // Fire & forget — the pull runs server-side
    fetch("/api/ollama", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "pull", model }),
    }).then(r => r.json()).then(d => {
      if (d.ok) setStatus("ready");
      else setStatus("error");
    }).catch(() => {
      // Don't set error — the pull may still be running, polling will catch it
    });
  };

  // Poll every 3s during download + elapsed timer
  useEffect(() => {
    if (status !== "downloading") return;
    const timer = setInterval(() => setElapsed(e => e + 3), 3000);
    const poller = setInterval(async () => {
      try {
        const res = await fetch("/api/ollama");
        const d = await res.json();
        const models = (d.models || []).map((m: { name: string }) => m.name);
        if (models.some((n: string) => n === model || n === model + ":latest")) {
          setStatus("ready");
        }
      } catch {}
    }, 3000);
    return () => { clearInterval(timer); clearInterval(poller); };
  }, [status, model]);

  if (status === "checking") return null;

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    return m > 0 ? `${m}min ${s % 60}s` : `${s}s`;
  };

  return (
    <div style={{ marginTop: "10px" }}>
      {status === "ready" && (
        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px", color: "var(--tc-green)" }}>
          <CheckCircle2 size={11} /> {tr("modelInstalled2", locale)}
        </div>
      )}
      {status === "not_found" && (
        <div>
          <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "6px" }}>
            {tr("modelNotInstalled", locale)}
          </div>
          <button onClick={startDownload} className="tc-btn-embossed" style={{ fontSize: "10px", padding: "6px 14px" }}>
            <Download size={11} /> {tr("downloadModel", locale)}
          </button>
        </div>
      )}
      {status === "downloading" && (
        <div>
          <div style={{ fontSize: "10px", color: "var(--tc-amber)", marginBottom: "6px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <Loader2 size={11} className="animate-spin" /> {tr("downloadInProgress", locale)}
            </span>
            <span style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>{formatTime(elapsed)}</span>
          </div>
          <div style={{ height: "6px", borderRadius: "3px", background: "var(--tc-input)", overflow: "hidden" }}>
            <div style={{
              height: "100%", borderRadius: "3px", background: "var(--tc-amber)",
              animation: "downloadPulse 2s ease-in-out infinite",
              width: elapsed < 30 ? "15%" : elapsed < 120 ? "40%" : elapsed < 300 ? "65%" : "85%",
              transition: "width 3s ease",
            }} />
          </div>
          <div style={{ fontSize: "8px", color: "var(--tc-text-muted)", marginTop: "4px" }}>
            {tr("downloadMayTakeMinutes", locale)}
          </div>
          <style>{`@keyframes downloadPulse { 0%,100% { opacity: 0.7; } 50% { opacity: 1; } }`}</style>
        </div>
      )}
      {status === "error" && (
        <div>
          <div style={{ fontSize: "10px", color: "var(--tc-red)", display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
            <AlertTriangle size={11} /> {tr("connectionError", locale)}
          </div>
          <button onClick={() => { setStatus("not_found"); }} className="tc-btn-embossed" style={{ fontSize: "9px", padding: "4px 10px" }}>
            {tr("retry", locale)}
          </button>
        </div>
      )}
    </div>
  );
}

function LlmTab({ llm, setLlm, conversational, setConversational, forensic, setForensic, instruct, setInstruct, cloud, setCloud, llmModels, setLlmModels, testOllama, inputStyle, labelStyle }: LlmTabProps) {
  const locale = useLocale();
  const [pullModel, setPullModel] = useState("");
  const [pulling, setPulling] = useState(false);
  const [pullStatus, setPullStatus] = useState<string | null>(null);
  const [showModels, setShowModels] = useState(false);
  const [testingModel, setTestingModel] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { ok: boolean; msg: string }>>({});
  const [cloudTesting, setCloudTesting] = useState(false);
  const [cloudTestResult, setCloudTestResult] = useState<{ ok: boolean; models?: string[]; error?: string } | null>(null);
  const [changingLevel, setChangingLevel] = useState<string | null>(null);

  const pullOllamaModel = async () => {
    if (!pullModel) return;
    setPulling(true);
    setPullStatus(`${tr("downloading", locale)} ${pullModel}...`);
    try {
      const res = await fetch("/api/ollama", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "pull", model: pullModel, url: llm.url }),
      });
      const data = await res.json();
      if (data.ok) {
        setPullStatus(`${pullModel} ${tr("modelPullDone", locale)}`);
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
        setPullStatus(`Error: ${data.error}`);
      }
    } catch (e) {
      setPullStatus(`Error: ${e instanceof Error ? e.message : "unknown"}`);
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
      setTestResult(p => ({ ...p, [model]: { ok: false, msg: tr("networkError", locale) } }));
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
      setCloudTestResult({ ok: false, error: tr("networkError", locale) });
    }
    setCloudTesting(false);
  };

  const modelOptions = llmModels.map(m => ({ value: m.name, label: m.name, detail: m.size }));

  const LevelBadge = ({ level, color, bg, border }: { level: string; color: string; bg: string; border: string }) => (
    <div style={{ minWidth: "32px", height: "32px", borderRadius: "var(--tc-radius-input)", background: bg, border: `1px solid ${border}`,
      display: "flex", alignItems: "center", justifyContent: "center", fontSize: level.length > 2 ? "10px" : "13px", fontWeight: 800, color, flexShrink: 0, padding: "0 6px" }}>
      {level}
    </div>
  );

  // AI level definitions — curated model catalog per level with RAM estimates
  const MODEL_CATALOG: Record<string, { value: string; label: string; detail: string; ram?: number }[]> = {
    l0: [
      { value: "gemma4:26b", label: "Gemma 4 26B MoE", detail: tr("modelDescGemma4_26b", locale), ram: 10 },
      { value: "mistral-small:24b", label: "Mistral Small 24B", detail: tr("modelDescMistralSmall", locale), ram: 14 },
      { value: "qwen3:14b", label: "Qwen3 14B", detail: tr("modelDescQwen14b", locale), ram: 9.3 },
      { value: "gemma4:e4b", label: "Gemma 4 E4B", detail: tr("modelDescGemma4_e4b", locale), ram: 3 },
      { value: "qwen3:8b", label: "Qwen3 8B", detail: tr("modelDescQwen8b", locale), ram: 5.2 },
    ],
    l1: [
      { value: "threatclaw-l1", label: "ThreatClaw AI 8B Triage", detail: tr("modelDescL1", locale), ram: 5.8 },
      { value: "gemma4:e4b", label: "Gemma 4 E4B Triage", detail: tr("modelDescGemma4_e4b_l1", locale), ram: 3 },
      { value: "qwen3:14b", label: "Qwen3 14B Triage", detail: tr("modelDescL1Alt", locale), ram: 9.3 },
    ],
    l2: [
      { value: "threatclaw-l2", label: "ThreatClaw AI 8B Reasoning", detail: tr("modelDescL2", locale), ram: 8.5 },
    ],
    l3: [
      { value: "threatclaw-l3", label: "ThreatClaw AI 8B Instruct", detail: tr("modelDescL3", locale), ram: 5.0 },
    ],
  };

  // RAM calculator
  const l0Ram = conversational.source === "local"
    ? (MODEL_CATALOG.l0.find(m => m.value === conversational.localModel)?.ram || 9.3)
    : 0;
  const l1Ram = MODEL_CATALOG.l1.find(m => m.value === (llm.model || "threatclaw-l1"))?.ram || 5.8;
  const l2Ram = MODEL_CATALOG.l2[0]?.ram || 8.5;
  const l3Ram = MODEL_CATALOG.l3[0]?.ram || 5.0;
  const permanentRam = l0Ram + l1Ram;
  const peakRam = permanentRam + Math.max(l2Ram, l3Ram);

  const aiLevels = [
    { id: "l1", level: "L1", name: "ThreatClaw AI 8B Triage", desc: "Pipeline auto — JSON structuré, classification, scoring", color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)", model: llm.model, defaultModel: "threatclaw-l1", setModel: (v: string) => setLlm(p => ({ ...p, model: v })) },
    { id: "l2", level: "L2", name: "ThreatClaw AI 8B Reasoning", desc: "Pipeline auto — Chain-of-thought, root cause, MITRE ATT&CK", color: "var(--tc-amber)", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)", model: forensic.model, defaultModel: "threatclaw-l2", setModel: (v: string) => setForensic(p => ({ ...p, model: v })) },
    { id: "l3", level: "L3", name: "ThreatClaw AI 8B Instruct", desc: "Enrichit les HITL — Playbooks SOAR, rapports, Sigma rules", color: "var(--tc-green)", bg: "rgba(48,160,80,0.08)", border: "rgba(48,160,80,0.2)", model: instruct.model, defaultModel: "threatclaw-l3", setModel: (v: string) => setInstruct(p => ({ ...p, model: v })) },
  ];

  return (
    <>
      {/* Architecture overview */}
      <ChromeInsetCard>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          {[
            { level: "L0", label: "Ops", desc: tr("aiLevelL0Desc", locale), color: "#d03020", bg: "rgba(208,48,32,0.08)", border: "rgba(208,48,32,0.2)" },
            { level: "L1", label: "Triage", desc: tr("aiLevelL1Desc", locale), color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
            { level: "L2", label: "Reasoning", desc: tr("aiLevelL2Desc", locale), color: "var(--tc-amber)", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
            { level: "L3", label: "Instruct", desc: tr("aiLevelL3Desc", locale), color: "var(--tc-green)", bg: "rgba(48,160,80,0.08)", border: "rgba(48,160,80,0.2)" },
            { level: "L4", label: "Cloud", desc: tr("aiLevelL4Desc", locale), color: "#a040d0", bg: "rgba(160,64,208,0.08)", border: "rgba(160,64,208,0.2)" },
          ].map(l => (
            <div key={l.level} style={{ flex: 1, minWidth: "80px", padding: "10px 8px", borderRadius: "var(--tc-radius-md)", background: l.bg, border: `1px solid ${l.border}`, textAlign: "center" }}>
              <div style={{ fontSize: "16px", fontWeight: 800, color: l.color }}>{l.level}</div>
              <div style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text)", marginTop: "2px" }}>{l.label}</div>
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{l.desc}</div>
            </div>
          ))}
        </div>
      </ChromeInsetCard>

      {/* ── RAM Usage Bar ── */}
      <ChromeInsetCard>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
          <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.5px" }}>{tr("ramEstimated", locale)}</span>
          <span style={{ fontSize: "12px", fontWeight: 600, color: peakRam > 28 ? "#d03020" : "var(--tc-text-muted)" }}>
            {permanentRam.toFixed(1)} GB {tr("permanent", locale)} · {peakRam.toFixed(1)} GB {tr("peak", locale)}
          </span>
        </div>
        <div style={{ height: "8px", borderRadius: "4px", background: "var(--tc-input)", overflow: "hidden", display: "flex" }}>
          {l0Ram > 0 && <div style={{ width: `${(l0Ram / 64) * 100}%`, background: "#d03020", transition: "width 0.3s" }} title={`L0: ${l0Ram} GB`} />}
          <div style={{ width: `${(l1Ram / 64) * 100}%`, background: "var(--tc-blue)", transition: "width 0.3s" }} title={`L1: ${l1Ram} GB`} />
          <div style={{ width: `${(Math.max(l2Ram, l3Ram) / 64) * 100}%`, background: "var(--tc-amber)", opacity: 0.4, transition: "width 0.3s" }} title={`L2/L3: ${Math.max(l2Ram, l3Ram)} GB (on-demand)`} />
        </div>
        <div style={{ display: "flex", gap: "12px", marginTop: "6px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
          {l0Ram > 0 && <span><span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "2px", background: "#d03020", marginRight: "4px" }} />L0: {l0Ram}GB</span>}
          <span><span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "2px", background: "var(--tc-blue)", marginRight: "4px" }} />L1: {l1Ram}GB</span>
          <span style={{ opacity: 0.6 }}><span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "2px", background: "var(--tc-amber)", marginRight: "4px" }} />L2/L3: {Math.max(l2Ram, l3Ram)}GB (swap)</span>
        </div>
      </ChromeInsetCard>

      {/* ── L0 — Conversational ── */}
      <ChromeInsetCard glow={conversational.source !== "disabled"}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: conversational.source !== "disabled" ? "16px" : 0 }}>
          <LevelBadge level="L0" color="#d03020" bg="rgba(208,48,32,0.12)" border="rgba(208,48,32,0.25)" />
          <div style={{ flex: 1 }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "15px", fontWeight: 700 }}>ThreatClaw AI Ops</ChromeEmbossedText>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("aiOpsDesc", locale)}</div>
          </div>
          <GlassSelect value={conversational.source} onChange={v => setConversational(p => ({ ...p, source: v as "disabled" | "local" | "cloud" }))} options={[
            { value: "disabled", label: tr("disabled", locale) },
            { value: "local", label: tr("local", locale) },
            { value: "cloud", label: tr("cloud", locale) },
          ]} />
        </div>

        {conversational.source === "local" && (
          <div style={{ borderTop: "1px solid var(--tc-border-light)", paddingTop: "14px" }}>
            <div style={labelStyle}>{tr("model", locale)}</div>
            <GlassSelect value={conversational.localModel} onChange={v => setConversational(p => ({ ...p, localModel: v }))}
              options={MODEL_CATALOG.l0.map(m => ({ value: m.value, label: m.label, detail: `${m.ram}GB — ${m.detail}` }))}
              placeholder={tr("selectModel", locale)} />
            {conversational.localModel.includes("mistral") && (
              <div style={{ fontSize: "10px", color: "var(--tc-green)", marginTop: "6px", display: "flex", alignItems: "center", gap: "4px" }}>
                <CheckCircle2 size={10} /> {tr("nativeToolCalling", locale)}
              </div>
            )}
            {conversational.localModel.includes("qwen") && (
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "6px" }}>
                {tr("promptToolCalling", locale)}
              </div>
            )}
            <ModelDownloadStatus model={conversational.localModel} ollamaUrl={llm.url} />
          </div>
        )}

        {conversational.source === "cloud" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "14px" }}>
            <div>
              <div style={labelStyle}>{tr("provider", locale)}</div>
              <GlassSelect value={conversational.cloudBackend} onChange={v => setConversational(p => ({ ...p, cloudBackend: v }))} options={[
                { value: "anthropic", label: tr("anthropicClaude", locale) },
                { value: "mistral", label: tr("mistralSovereign", locale) },
                { value: "openai_compatible", label: tr("openaiCompatible", locale) },
              ]} />
            </div>
            <div>
              <div style={labelStyle}>{tr("apiKey", locale)}</div>
              <input style={inputStyle} type="password" value={conversational.cloudApiKey}
                onChange={e => setConversational(p => ({ ...p, cloudApiKey: e.target.value }))}
                placeholder={conversational.cloudBackend === "anthropic" ? "sk-ant-..." : "..."} />
            </div>
            <div>
              <div style={labelStyle}>Modèle</div>
              <input style={inputStyle} value={conversational.cloudModel}
                onChange={e => setConversational(p => ({ ...p, cloudModel: e.target.value }))}
                placeholder={conversational.cloudBackend === "anthropic" ? "claude-sonnet-4-20250514" : conversational.cloudBackend === "mistral" ? "mistral-large-latest" : "gpt-4o"} />
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <button onClick={() => setConversational(p => ({ ...p, anonymize: !p.anonymize }))}
                style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                <div style={{
                  width: "36px", height: "20px", borderRadius: "10px", position: "relative",
                  background: conversational.anonymize ? "rgba(48,160,80,0.2)" : "var(--tc-input)",
                  border: conversational.anonymize ? "1px solid rgba(48,160,80,0.3)" : "1px solid var(--tc-border)",
                  transition: "all 0.25s",
                }}>
                  <div style={{
                    width: "14px", height: "14px", borderRadius: "50%", position: "absolute", top: "2px",
                    left: conversational.anonymize ? "19px" : "2px",
                    background: conversational.anonymize ? "var(--tc-green)" : "var(--tc-text-muted)",
                    transition: "all 0.25s",
                  }} />
                </div>
              </button>
              <div>
                <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>{tr("anonymization", locale)}</div>
                <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
                  {conversational.anonymize ? tr("anonymizeOn", locale) : tr("anonymizeOff", locale)}
                </div>
              </div>
            </div>
          </div>
        )}
      </ChromeInsetCard>

      {/* ── AI Levels ── */}
      {aiLevels.map(ai => (
        <ChromeInsetCard key={ai.id}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <LevelBadge level={ai.level} color={ai.color} bg={ai.bg} border={ai.border} />
            <div style={{ flex: 1 }}>
              <ChromeEmbossedText as="div" style={{ fontSize: "14px", fontWeight: 700 }}>{ai.name}</ChromeEmbossedText>
              <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{ai.desc}</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "13px", fontWeight: 600, color: ai.model ? ai.color : "var(--tc-text-muted)", fontFamily: "monospace" }}>
                {ai.model || ai.defaultModel}
              </span>
              <ChromeButton onClick={() => setChangingLevel(changingLevel === ai.id ? null : ai.id)} variant="glass">
                {changingLevel === ai.id ? <X size={12} /> : <Settings size={12} />}
                {changingLevel === ai.id ? tr("close", locale) : tr("change", locale)}
              </ChromeButton>
            </div>
          </div>
          {changingLevel === ai.id && (
            <div style={{ marginTop: "14px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "14px" }}>
              <GlassSelect value={ai.model || ai.defaultModel} onChange={v => ai.setModel(v)}
                options={MODEL_CATALOG[ai.id] || [{ value: ai.defaultModel, label: ai.defaultModel, detail: tr("default2", locale) }]}
                placeholder={tr("selectModel", locale)} />
              {(MODEL_CATALOG[ai.id] || []).length <= 1 && (
                <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "8px", fontStyle: "italic" }}>
                  {tr("moreModelsLater", locale)}
                </div>
              )}
            </div>
          )}
        </ChromeInsetCard>
      ))}

      {/* ── L4 — Cloud ── */}
      <ChromeInsetCard glow={cloud.enabled}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: cloud.enabled ? "16px" : 0 }}>
          <LevelBadge level="L4" color="#a040d0" bg="rgba(160,64,208,0.12)" border="rgba(160,64,208,0.25)" />
          <div style={{ flex: 1 }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "15px", fontWeight: 700 }}>{tr("cloudEscalation", locale)}</ChromeEmbossedText>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("cloudEscalationDesc", locale)}</div>
          </div>
          <button onClick={() => setCloud(p => ({ ...p, enabled: !p.enabled }))}
            style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
            <div style={{
              width: "44px", height: "24px", borderRadius: "var(--tc-radius-card)", position: "relative",
              background: cloud.enabled ? "rgba(160,64,208,0.15)" : "var(--tc-input)",
              border: cloud.enabled ? "1px solid rgba(160,64,208,0.3)" : "1px solid var(--tc-input)",
              transition: "all 0.25s ease",
            }}>
              <div style={{
                width: "18px", height: "18px", borderRadius: "50%", position: "absolute", top: "2px",
                left: cloud.enabled ? "23px" : "2px",
                background: cloud.enabled ? "#a040d0" : "var(--tc-text-muted)",
                transition: "all 0.25s ease",
              }} />
            </div>
          </button>
        </div>

        {cloud.enabled && (
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "16px" }}>
            <div>
              <div style={labelStyle}>{tr("provider", locale)}</div>
              <GlassSelect value={cloud.backend} onChange={v => setCloud(p => ({ ...p, backend: v }))} options={[
                { value: "anthropic", label: tr("anthropicClaude", locale) },
                { value: "mistral", label: tr("mistralSovereign", locale) },
                { value: "openai_compatible", label: tr("openaiCompatible", locale) },
              ]} />
            </div>
            <div>
              <div style={labelStyle}>{tr("apiKey", locale)}</div>
              <div style={{ display: "flex", gap: "8px" }}>
                <input style={{ ...inputStyle, flex: 1 }} type="password" value={cloud.apiKey}
                  onChange={e => setCloud(p => ({ ...p, apiKey: e.target.value }))}
                  placeholder={cloud.backend === "anthropic" ? "sk-ant-..." : cloud.backend === "mistral" ? "..." : "sk-..."} />
                <ChromeButton onClick={testCloudApi} disabled={cloudTesting || !cloud.apiKey} variant={cloudTestResult?.ok ? "glass" : "primary"}>
                  {cloudTesting ? <Loader2 size={14} className="animate-spin" /> : cloudTestResult?.ok ? <CheckCircle2 size={14} color="#30a050" /> : <Cloud size={14} />}
                  {tr("test", locale)}
                </ChromeButton>
              </div>
              {cloudTestResult && (
                <div style={{ fontSize: "12px", marginTop: "8px", color: cloudTestResult.ok ? "#30a050" : "#d03020", display: "flex", alignItems: "center", gap: "6px" }}>
                  {cloudTestResult.ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                  {cloudTestResult.ok
                    ? `${tr("connected", locale)} — ${cloudTestResult.models?.length || 0} ${tr("modelsAvailable", locale)}`
                    : cloudTestResult.error}
                </div>
              )}
            </div>
            <div>
              <div style={labelStyle}>{tr("model", locale)}</div>
              {cloudTestResult?.ok && cloudTestResult.models && cloudTestResult.models.length > 0 ? (
                <GlassSelect value={cloud.model} onChange={v => setCloud(p => ({ ...p, model: v }))}
                  options={cloudTestResult.models.map(m => ({ value: m, label: m }))} placeholder={tr("selectModel", locale)} />
              ) : (
                <input style={inputStyle} value={cloud.model} onChange={e => setCloud(p => ({ ...p, model: e.target.value }))}
                  placeholder={cloud.backend === "anthropic" ? "claude-sonnet-4-20250514" : cloud.backend === "mistral" ? "mistral-large-latest" : "gpt-4o"} />
              )}
            </div>
            <div>
              <div style={labelStyle}>{tr("anonymization", locale)}</div>
              <GlassSelect value={cloud.escalation} onChange={v => setCloud(p => ({ ...p, escalation: v }))} options={[
                { value: "anonymized", label: tr("anonymized", locale), detail: tr("anonymizedDesc", locale) },
                { value: "direct", label: tr("direct", locale), detail: tr("directDesc", locale) },
                { value: "never", label: tr("cloudDisabled", locale), detail: tr("cloudDisabledDesc", locale) },
              ]} />
            </div>
          </div>
        )}
      </ChromeInsetCard>
    </>
  );
}

// ═══════════════════════════════════════
// ENRICHMENT TAB — sources status + sync
// ═══════════════════════════════════════

// Enrichment sources — desc/enriches/help use i18n keys, resolved at render time
const ENRICHMENT_SOURCES_DEF = [
  { id: "nvd", name: "NVD NIST", descKey: "enrNvdDesc", enrichesKey: "enrNvdEnriches", helpKey: "enrNvdHelp", free: true, noKey: false, syncable: false },
  { id: "cisa_kev", name: "CISA KEV", descKey: "enrCisaDesc", enrichesKey: "enrCisaEnriches", helpKey: "enrCisaHelp", free: true, noKey: true, syncable: true, syncUrl: "/api/tc/enrichment/kev/sync" },
  { id: "mitre", name: "MITRE ATT&CK", descKey: "enrMitreDesc", enrichesKey: "enrMitreEnriches", helpKey: "enrMitreHelp", free: true, noKey: true, syncable: true, syncUrl: "/api/tc/enrichment/mitre/sync" },
  { id: "certfr", name: "CERT-FR", descKey: "enrCertfrDesc", enrichesKey: "enrCertfrEnriches", helpKey: "enrCertfrHelp", free: true, noKey: true, syncable: true, syncUrl: "/api/tc/enrichment/certfr/sync" },
  { id: "openphish", name: "OpenPhish", descKey: "enrOpenphishDesc", enrichesKey: "enrOpenphishEnriches", helpKey: "enrOpenphishHelp", free: true, noKey: true, syncable: true, syncUrl: "/api/tc/enrichment/openphish/sync" },
  { id: "greynoise", name: "GreyNoise", descKey: "enrGreynoiseDesc", enrichesKey: "enrGreynoiseEnriches", helpKey: "enrGreynoiseHelp", free: true, noKey: true, syncable: false, onDemand: true },
  { id: "threatfox", name: "ThreatFox", descKey: "enrThreatfoxDesc", enrichesKey: "enrThreatfoxEnriches", helpKey: "enrThreatfoxHelp", free: true, noKey: false, syncable: false, onDemand: true },
  { id: "malware_bazaar", name: "MalwareBazaar", descKey: "enrMalwareDesc", enrichesKey: "enrMalwareEnriches", helpKey: "enrMalwareHelp", free: true, noKey: false, syncable: false, onDemand: true },
  { id: "urlhaus", name: "URLhaus", descKey: "enrUrlhausDesc", enrichesKey: "enrUrlhausEnriches", helpKey: "enrUrlhausHelp", free: true, noKey: false, syncable: false, onDemand: true },
  { id: "epss", name: "EPSS (FIRST.org)", descKey: "enrEpssDesc", enrichesKey: "enrEpssEnriches", helpKey: "enrEpssHelp", free: true, noKey: true, syncable: false, onDemand: true },
  { id: "ipinfo", name: "IPinfo", descKey: "enrIpinfoDesc", enrichesKey: "enrIpinfoEnriches", helpKey: "enrIpinfoHelp", free: true, noKey: true, syncable: false, onDemand: true },
  { id: "crowdsec", name: "CrowdSec CTI", descKey: "enrCrowdsecDesc", enrichesKey: "enrCrowdsecEnriches", helpKey: "enrCrowdsecHelp", free: true, noKey: false, syncable: false, onDemand: true },
];

function EnrichmentTab() {
  const locale = useLocale();
  const [status, setStatus] = useState<Record<string, { status: string; meta?: Record<string, unknown>; cache_count?: number; count?: number; synced_at?: string }>>({});
  const [syncing, setSyncing] = useState<string | null>(null);
  const [syncAllRunning, setSyncAllRunning] = useState(false);
  const [helpOpen, setHelpOpen] = useState<string | null>(null);
  const [enabled, setEnabled] = useState<Record<string, boolean>>({});
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [savingEnabled, setSavingEnabled] = useState(false);

  useEffect(() => {
    fetch("/api/tc/enrichment/status").then(r => r.json()).then(d => setStatus(d)).catch(() => {});
    // Load enabled state
    fetch("/api/tc/config").then(r => r.json()).then(cfg => {
      if (cfg.enrichment_enabled) setEnabled(cfg.enrichment_enabled);
      if (cfg.enrichment_keys) setApiKeys(cfg.enrichment_keys);
      if (!cfg.enrichment_enabled) {
        // Default: all free sources enabled
        const defaults: Record<string, boolean> = {};
        ENRICHMENT_SOURCES_DEF.forEach(s => { defaults[s.id] = s.noKey; });
        setEnabled(defaults);
      }
    }).catch(() => {
      const defaults: Record<string, boolean> = {};
      ENRICHMENT_SOURCES_DEF.forEach(s => { defaults[s.id] = s.noKey; });
      setEnabled(defaults);
    });
  }, []);

  const toggleSource = async (id: string) => {
    const next = { ...enabled, [id]: !enabled[id] };
    setEnabled(next);
    saveEnrichmentConfig(next, apiKeys);
  };

  const updateApiKey = async (id: string, key: string) => {
    const next = { ...apiKeys, [id]: key };
    setApiKeys(next);
  };

  const saveApiKey = async (id: string) => {
    saveEnrichmentConfig(enabled, apiKeys);
  };

  const saveEnrichmentConfig = async (en: Record<string, boolean>, keys: Record<string, string>) => {
    setSavingEnabled(true);
    try {
      await fetch("/api/tc/config", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enrichment_enabled: en, enrichment_keys: keys }),
      });
    } catch { /* */ }
    setSavingEnabled(false);
  };

  const syncSource = async (id: string, url: string) => {
    setSyncing(id);
    try {
      await fetch(url, { method: "POST" });
      const res = await fetch("/api/tc/enrichment/status");
      const d = await res.json();
      setStatus(d);
    } catch { /* */ }
    setSyncing(null);
  };

  const syncAll = async () => {
    setSyncAllRunning(true);
    try {
      await fetch("/api/tc/enrichment/sync-all", { method: "POST" });
      const res = await fetch("/api/tc/enrichment/status");
      const d = await res.json();
      setStatus(d);
    } catch { /* */ }
    setSyncAllRunning(false);
  };

  return (
    <>
      <ChromeInsetCard>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, display: "flex", alignItems: "center", gap: "10px" }}>
            <Database size={18} color="#d03020" /> {tr("enrichmentSources", locale)}
          </ChromeEmbossedText>
          <ChromeButton onClick={syncAll} disabled={syncAllRunning} variant="primary">
            {syncAllRunning ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            {syncAllRunning ? tr("syncing", locale) : tr("syncAll", locale)}
          </ChromeButton>
        </div>
        <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginBottom: "20px", lineHeight: 1.6 }}>
          {tr("enrIntro", locale)}
          <br />{locale === "fr" ? "La plupart sont" : "Most are"} <strong style={{ color: "var(--tc-green)" }}>{tr("enrFreeNoSignup", locale)}</strong>. {locale === "fr" ? "Celles marquées" : "Those marked"} <span style={{ color: "var(--tc-amber)" }}>{tr("requiredKey", locale)}</span> {locale === "fr" ? "nécessitent une inscription gratuite." : "require free registration."}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {ENRICHMENT_SOURCES_DEF.map(src => {
            const st = status[src.id];
            const isSynced = st?.status === "synced" || st?.status === "active";
            const count = st?.cache_count || st?.count || (st?.meta as Record<string, unknown>)?.count || (st?.meta as Record<string, unknown>)?.technique_count;

            return (
              <div key={src.id} style={{
                padding: "12px 14px", borderRadius: "var(--tc-radius-md)",
                background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                {/* Toggle */}
                <input type="checkbox" className="tc-toggle" checked={!!enabled[src.id]}
                  onChange={() => toggleSource(src.id)} />
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)" }}>{src.name}</span>
                    {!src.noKey && src.id === "nvd" && <span style={{ fontSize: "9px", color: "var(--tc-blue)", padding: "1px 4px", borderRadius: "3px", background: "rgba(48,128,208,0.08)", border: "1px solid rgba(48,128,208,0.15)" }}>{tr("optionalKey", locale)}</span>}
                    {!src.noKey && src.id !== "nvd" && <span style={{ fontSize: "9px", color: "var(--tc-amber)", padding: "1px 4px", borderRadius: "3px", background: "rgba(208,144,32,0.08)", border: "1px solid rgba(208,144,32,0.15)" }}>{tr("requiredKey", locale)}</span>}
                    <button onClick={() => setHelpOpen(helpOpen === src.id ? null : src.id)} style={{ background: "none", border: "none", cursor: "pointer", padding: "2px" }}>
                      <HelpCircle size={13} color="var(--tc-text-muted)" />
                    </button>
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr(src.descKey, locale)}</div>
                  <div style={{ fontSize: "10px", color: "var(--tc-blue)", marginTop: "2px" }}>{tr(src.enrichesKey, locale)}</div>
                </div>
                {count !== undefined && count !== null && (
                  <span style={{ fontSize: "11px", color: "var(--tc-green)", fontFamily: "monospace" }}>
                    {String(count)} entries
                  </span>
                )}
                <span style={{
                  fontSize: "9px", fontWeight: 600, padding: "2px 6px", borderRadius: "4px",
                  background: (isSynced || src.onDemand) ? "rgba(48,160,80,0.08)" : "var(--tc-input)",
                  color: (isSynced || src.onDemand) ? "#30a050" : "var(--tc-text-muted)",
                  border: `1px solid ${(isSynced || src.onDemand) ? "rgba(48,160,80,0.15)" : "var(--tc-input)"}`,
                }}>
                  {src.onDemand ? tr("activeOnDemand", locale) : isSynced ? tr("synchronized", locale) : tr("notSynchronized", locale)}
                </span>
                {src.syncable && (
                  <ChromeButton onClick={() => syncSource(src.id, src.syncUrl!)} disabled={syncing === src.id} variant="glass">
                    {syncing === src.id ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                  </ChromeButton>
                )}
                </div>
                {/* API key input for sources that need one */}
                {!src.noKey && enabled[src.id] && (
                  <div style={{ marginTop: "10px", display: "flex", gap: "8px", alignItems: "center" }}>
                    <Key size={14} color="#d09020" style={{ flexShrink: 0 }} />
                    <input
                      type="password"
                      value={apiKeys[src.id] || ""}
                      onChange={e => updateApiKey(src.id, e.target.value)}
                      onBlur={() => saveApiKey(src.id)}
                      placeholder={tr("enrichmentApiKeyHint", locale).replace("{0}", src.name)}
                      style={{
                        flex: 1, background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                        borderRadius: "var(--tc-radius-input)", padding: "8px 12px", fontSize: "12px", color: "var(--tc-text)",
                        fontFamily: "inherit", outline: "none",
                      }}
                    />
                    {apiKeys[src.id] && (
                      <CheckCircle2 size={14} color="#30a050" style={{ flexShrink: 0 }} />
                    )}
                  </div>
                )}
                {helpOpen === src.id && (
                  <div style={{ marginTop: "10px", padding: "10px 12px", borderRadius: "var(--tc-radius-input)", background: "rgba(48,128,208,0.04)", border: "1px solid rgba(48,128,208,0.1)", fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                    {tr(src.helpKey, locale)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </ChromeInsetCard>

      <ChromeInsetCard>
        <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", lineHeight: 1.7 }}>
          <strong style={{ color: "var(--tc-text)" }}>{tr("enrVsSkillsTitle", locale)}</strong>
          <br /><br />
          {tr("enrVsSkillsBody1", locale)}
          <br /><br />
          {tr("enrVsSkillsBody2", locale)}
        </div>
      </ChromeInsetCard>
    </>
  );
}

// ═══════════════════════════════════════
// NOTIFICATIONS TAB — routing matrix
// ═══════════════════════════════════════

const NOTIFICATION_LEVELS = [
  { id: "digest", labelKey: "digestDaily", descKey: "digestDailyDesc", color: "var(--tc-blue)" },
  { id: "alert", labelKey: "alertNotif", descKey: "alertNotifDesc", color: "var(--tc-amber)" },
  { id: "critical", labelKey: "criticalNotif", descKey: "criticalNotifDesc", color: "var(--tc-red)" },
];

const ALL_CHANNELS = [
  { id: "telegram", label: "Telegram" },
  { id: "slack", label: "Slack" },
  { id: "mattermost", label: "Mattermost" },
  { id: "ntfy", label: "Ntfy" },
  { id: "gotify", label: "Gotify" },
  { id: "email", label: "Email" },
];

function NotificationsTab({ inputStyle, labelStyle }: { inputStyle: React.CSSProperties; labelStyle: React.CSSProperties }) {
  const locale = useLocale();
  const [routing, setRouting] = useState<Record<string, string[]>>({ digest: ["telegram"], alert: ["telegram"], critical: ["telegram", "ntfy"] });
  const [configuredChannels, setConfiguredChannels] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [situation, setSituation] = useState<{ global_score?: number; notification_level?: string; open_findings?: number; active_alerts?: number } | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResults, setTestResults] = useState<{ channel: string; ok: boolean; error?: string }[]>([]);

  useEffect(() => {
    // Load routing config
    fetch("/api/tc/notifications/routing").then(r => r.json()).then(d => {
      if (d.digest) setRouting(d);
    }).catch(() => {});

    // Load configured channels
    fetch("/api/tc/config").then(r => r.json()).then(cfg => {
      const channels = cfg.channels || {};
      const configured: string[] = [];
      if (channels.telegram?.enabled && channels.telegram?.botToken) configured.push("telegram");
      if (channels.slack?.enabled && channels.slack?.botToken) configured.push("slack");
      if (channels.discord?.enabled && channels.discord?.botToken) configured.push("discord");
      if (channels.mattermost?.enabled && channels.mattermost?.webhookUrl) configured.push("mattermost");
      if (channels.ntfy?.enabled && channels.ntfy?.topic) configured.push("ntfy");
      if (channels.gotify?.enabled && channels.gotify?.appToken) configured.push("gotify");
      if (channels.email?.enabled && channels.email?.host) configured.push("email");
      if (channels.signal?.enabled && channels.signal?.account) configured.push("signal");
      if (channels.whatsapp?.enabled && channels.whatsapp?.accessToken) configured.push("whatsapp");
      setConfiguredChannels(configured);
    }).catch(() => {});

    // Load current situation
    fetch("/api/tc/intelligence/situation").then(r => r.json()).then(d => setSituation(d)).catch(() => {});
  }, []);

  const toggleChannel = (level: string, channel: string) => {
    setRouting(prev => {
      const current = prev[level] || [];
      const next = current.includes(channel)
        ? current.filter(c => c !== channel)
        : [...current, channel];
      return { ...prev, [level]: next };
    });
  };

  const saveRouting = async () => {
    setSaving(true);
    try {
      await fetch("/api/tc/notifications/routing", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(routing),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch { /* */ }
    setSaving(false);
  };

  const testNotification = async (level: string) => {
    setTesting(true);
    setTestResults([]);
    try {
      const res = await fetch("/api/tc/notifications/test", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ level, message: `ThreatClaw — Test notification (${level})` }),
      });
      const data = await res.json();
      setTestResults(data.results || []);
    } catch { /* */ }
    setTesting(false);
  };

  return (
    <>
      {/* Current situation */}
      {situation && situation.global_score !== undefined && (
        <ChromeInsetCard>
          <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px" }}>
            <Shield size={18} color="#d03020" /> {tr("currentSituation", locale)}
          </ChromeEmbossedText>
          <div style={{ display: "flex", gap: "16px" }}>
            <div style={{ textAlign: "center", padding: "12px 20px", borderRadius: "var(--tc-radius-md)", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)" }}>
              <div style={{ fontSize: "28px", fontWeight: 800, color: (situation.global_score ?? 100) >= 70 ? "#30a050" : (situation.global_score ?? 100) >= 40 ? "#d09020" : "#d03020" }}>
                {Math.round(situation.global_score ?? 100)}
              </div>
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", textTransform: "uppercase" }}>Score</div>
            </div>
            <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center", gap: "4px" }}>
              <div style={{ fontSize: "13px", color: "var(--tc-text)" }}>
                Niveau : <strong style={{ color: situation.notification_level === "silence" ? "#30a050" : situation.notification_level === "digest" ? "#3080d0" : situation.notification_level === "alert" ? "#d09020" : "#d03020" }}>
                  {situation.notification_level || "silence"}
                </strong>
              </div>
              <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
                {situation.open_findings || 0} {tr("openFindings", locale)}{situation.active_alerts || 0} {tr("activeAlerts", locale)}
              </div>
            </div>
          </div>
        </ChromeInsetCard>
      )}

      {/* No channels warning */}
      {configuredChannels.length === 0 && (
        <ChromeInsetCard glow>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <AlertTriangle size={20} color="#d03020" />
            <div>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-red)" }}>{tr("noChannelConfigured", locale)}</div>
              <div style={{ fontSize: "12px", color: "var(--tc-text-muted)" }}>
                {locale === "fr" ? "Allez dans l'onglet Canaux pour configurer au moins un moyen de communication." : "Go to the Channels tab to configure at least one communication channel."}
              </div>
            </div>
          </div>
        </ChromeInsetCard>
      )}

      {/* Routing matrix */}
      <ChromeInsetCard>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, marginBottom: "8px", display: "flex", alignItems: "center", gap: "10px" }}>
          <Bell size={18} color="#d03020" /> {tr("notifRouting", locale)}
        </ChromeEmbossedText>
        <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginBottom: "20px" }}>
          {tr("notifRoutingDesc", locale)}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {NOTIFICATION_LEVELS.map(level => (
            <div key={level.id} style={{ padding: "14px 16px", borderRadius: "var(--tc-radius-card)", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
                <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: level.color, boxShadow: `0 0 6px ${level.color}40` }} />
                <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>{tr(level.labelKey, locale)}</span>
                <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>— {tr(level.descKey, locale)}</span>
              </div>
              <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                {ALL_CHANNELS.map(ch => {
                  const active = (routing[level.id] || []).includes(ch.id);
                  const configured = configuredChannels.includes(ch.id);
                  return (
                    <button key={ch.id} onClick={() => configured && toggleChannel(level.id, ch.id)}
                      disabled={!configured}
                      style={{
                        padding: "6px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "11px", fontWeight: 600,
                        fontFamily: "inherit", cursor: configured ? "pointer" : "not-allowed",
                        background: active ? `${level.color}15` : "var(--tc-surface-alt)",
                        border: `1px solid ${active ? `${level.color}40` : "var(--tc-input)"}`,
                        color: active ? level.color : configured ? "var(--tc-text-muted)" : "#3a3a3a",
                        opacity: configured ? 1 : 0.4,
                        transition: "all 0.2s",
                      }}>
                      {ch.label}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "16px" }}>
          <div style={{ display: "flex", gap: "6px" }}>
            {NOTIFICATION_LEVELS.map(level => (
              <ChromeButton key={level.id} onClick={() => testNotification(level.id)} disabled={testing} variant="glass">
                <Play size={12} /> Test {tr(level.labelKey, locale).toLowerCase()}
              </ChromeButton>
            ))}
          </div>
          <ChromeButton onClick={saveRouting} disabled={saving} variant="primary" style={{ minWidth: "140px" }}>
            {saving ? <Loader2 size={14} className="animate-spin" /> : saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
            {saved ? `${tr("save", locale)} ✓` : tr("save", locale)}
          </ChromeButton>
        </div>

        {/* Test results */}
        {testResults.length > 0 && (
          <div style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "4px" }}>
            {testResults.map((r, i) => (
              <div key={i} style={{ fontSize: "11px", display: "flex", alignItems: "center", gap: "6px", color: r.ok ? "#30a050" : "#d03020" }}>
                {r.ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                {r.channel}: {r.ok ? "OK" : r.error}
              </div>
            ))}
          </div>
        )}
      </ChromeInsetCard>

      {/* Advanced notification settings */}
      <NotificationSettingsSection inputStyle={inputStyle} labelStyle={labelStyle} />

      {/* Explanation */}
      <ChromeInsetCard>
        <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", lineHeight: 1.7 }}>
          <strong style={{ color: "var(--tc-text)" }}>{tr("notifHowTitle", locale)}</strong>
          <br /><br />
          {tr("notifHowBody", locale)}
        </div>
      </ChromeInsetCard>
    </>
  );
}

// ── Advanced notification settings component ──

function NotificationSettingsSection({ inputStyle, labelStyle }: { inputStyle: React.CSSProperties; labelStyle: React.CSSProperties }) {
  const locale = useLocale();
  const [settings, setSettings] = useState({
    cooldown_critical_secs: 7200,
    cooldown_high_secs: 43200,
    cooldown_medium_secs: 86400,
    cooldown_low_secs: 0,
    min_severity: "HIGH",
    remind_unresolved_critical_secs: 14400,
    remind_unresolved_high_secs: 0,
    escalation_always_notify: true,
    quiet_hours_enabled: false,
    quiet_hours_min_severity: "CRITICAL",
    daily_digest_enabled: true,
    daily_digest_time: "08:00",
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetch("/api/tc/notifications/settings").then(r => r.json()).then(d => {
      if (d.cooldown_critical_secs !== undefined) setSettings(d);
    }).catch(() => {});
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      await fetch("/api/tc/notifications/settings", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch { /* */ }
    setSaving(false);
  };

  const secsToHours = (secs: number) => secs > 0 ? Math.round(secs / 3600) : 0;
  const hoursToSecs = (hours: number) => hours * 3600;

  const rowStyle: React.CSSProperties = { display: "flex", alignItems: "center", gap: "12px", marginBottom: "10px" };
  const dotStyle = (color: string): React.CSSProperties => ({ width: "10px", height: "10px", borderRadius: "50%", background: color, boxShadow: `0 0 6px ${color}40`, flexShrink: 0 });
  const smallInput: React.CSSProperties = { ...inputStyle, width: "70px", textAlign: "center" as const };
  const toggleStyle = (active: boolean): React.CSSProperties => ({
    width: "38px", height: "18px", borderRadius: "9px", border: "none", cursor: "pointer",
    background: active ? "#30a050" : "var(--tc-input)", position: "relative" as const, transition: "all 0.2s",
  });
  const toggleDot = (active: boolean): React.CSSProperties => ({
    position: "absolute" as const, top: "2px", left: active ? "22px" : "2px",
    width: "14px", height: "14px", borderRadius: "50%", background: "#fff", transition: "left 0.2s",
  });

  return (
    <ChromeInsetCard>
      <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, marginBottom: "6px", display: "flex", alignItems: "center", gap: "10px" }}>
        <Settings size={18} color="#d03020" /> {tr("notifSettingsTitle", locale)}
      </ChromeEmbossedText>
      <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginBottom: "20px" }}>{tr("notifSettingsDesc", locale)}</div>

      {/* Cooldowns per severity */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ ...labelStyle, marginBottom: "10px" }}>{tr("notifCooldowns", locale)}</div>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>{tr("notifCooldownDesc", locale)}</div>
        {([
          { key: "cooldown_critical_secs" as const, color: "#d03020", label: "CRITICAL" },
          { key: "cooldown_high_secs" as const, color: "#d09020", label: "HIGH" },
          { key: "cooldown_medium_secs" as const, color: "#d0c020", label: "MEDIUM" },
          { key: "cooldown_low_secs" as const, color: "#3080d0", label: "LOW" },
        ]).map(({ key, color, label }) => (
          <div key={key} style={rowStyle}>
            <div style={dotStyle(color)} />
            <span style={{ fontSize: "12px", fontWeight: 700, width: "70px", color: "var(--tc-text)" }}>{label}</span>
            {key === "cooldown_low_secs" ? (
              <GlassSelect value={settings[key] === 0 ? "never" : String(secsToHours(settings[key]))}
                onChange={v => setSettings(s => ({ ...s, [key]: v === "never" ? 0 : hoursToSecs(parseInt(v)) }))}
                options={[
                  { value: "never", label: tr("notifNever", locale) },
                  { value: "24", label: "24h" }, { value: "48", label: "48h" }, { value: "72", label: "72h" },
                ]} />
            ) : (
              <>
                <input type="number" min={key === "cooldown_critical_secs" ? 1 : 2} max={72} value={secsToHours(settings[key])}
                  onChange={e => setSettings(s => ({ ...s, [key]: hoursToSecs(Math.max(1, parseInt(e.target.value) || 1)) }))}
                  style={smallInput} />
                <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("notifHours", locale)}</span>
              </>
            )}
          </div>
        ))}
      </div>

      {/* Minimum severity */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ ...labelStyle, marginBottom: "6px" }}>{tr("notifMinSeverity", locale)}</div>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "8px" }}>{tr("notifMinSeverityDesc", locale)}</div>
        <GlassSelect value={settings.min_severity}
          onChange={v => setSettings(s => ({ ...s, min_severity: v }))}
          options={[
            { value: "CRITICAL", label: "CRITICAL" },
            { value: "HIGH", label: "HIGH+" },
            { value: "MEDIUM", label: "MEDIUM+" },
            { value: "LOW", label: locale === "fr" ? "Tout" : "All" },
          ]} />
      </div>

      {/* Remind if unresolved */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ ...labelStyle, marginBottom: "6px" }}>{tr("notifRemindTitle", locale)}</div>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "10px" }}>{tr("notifRemindDesc", locale)}</div>
        {([
          { key: "remind_unresolved_critical_secs" as const, color: "#d03020", label: "CRITICAL" },
          { key: "remind_unresolved_high_secs" as const, color: "#d09020", label: "HIGH" },
        ]).map(({ key, color, label }) => (
          <div key={key} style={rowStyle}>
            <div style={dotStyle(color)} />
            <span style={{ fontSize: "12px", fontWeight: 700, width: "70px", color: "var(--tc-text)" }}>{label}</span>
            <button style={toggleStyle(settings[key] > 0)}
              onClick={() => setSettings(s => ({ ...s, [key]: s[key] > 0 ? 0 : (key.includes("critical") ? 14400 : 28800) }))}>
              <div style={toggleDot(settings[key] > 0)} />
            </button>
            {settings[key] > 0 && (
              <>
                <input type="number" min={1} max={48} value={secsToHours(settings[key])}
                  onChange={e => setSettings(s => ({ ...s, [key]: hoursToSecs(Math.max(1, parseInt(e.target.value) || 1)) }))}
                  style={smallInput} />
                <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("notifHours", locale)}</span>
              </>
            )}
          </div>
        ))}
      </div>

      {/* Escalation toggle */}
      <div style={{ ...rowStyle, marginBottom: "20px" }}>
        <button style={toggleStyle(settings.escalation_always_notify)}
          onClick={() => setSettings(s => ({ ...s, escalation_always_notify: !s.escalation_always_notify }))}>
          <div style={toggleDot(settings.escalation_always_notify)} />
        </button>
        <div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{tr("notifEscalation", locale)}</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("notifEscalationDesc", locale)}</div>
        </div>
      </div>

      {/* Quiet hours toggle */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ ...rowStyle, marginBottom: "8px" }}>
          <button style={toggleStyle(settings.quiet_hours_enabled)}
            onClick={() => setSettings(s => ({ ...s, quiet_hours_enabled: !s.quiet_hours_enabled }))}>
            <div style={toggleDot(settings.quiet_hours_enabled)} />
          </button>
          <div>
            <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{tr("notifQuietHours", locale)}</div>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("notifQuietHoursDesc", locale)}</div>
          </div>
        </div>
        {settings.quiet_hours_enabled && (
          <div style={{ ...rowStyle, paddingLeft: "50px" }}>
            <span style={{ fontSize: "12px", color: "var(--tc-text)" }}>{tr("notifQuietMinSeverity", locale)}</span>
            <GlassSelect value={settings.quiet_hours_min_severity}
              onChange={v => setSettings(s => ({ ...s, quiet_hours_min_severity: v }))}
              options={[
                { value: "CRITICAL", label: "CRITICAL" },
                { value: "HIGH", label: "HIGH+" },
              ]} />
          </div>
        )}
      </div>

      {/* Daily digest */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ ...rowStyle, marginBottom: "8px" }}>
          <button style={toggleStyle(settings.daily_digest_enabled)}
            onClick={() => setSettings(s => ({ ...s, daily_digest_enabled: !s.daily_digest_enabled }))}>
            <div style={toggleDot(settings.daily_digest_enabled)} />
          </button>
          <div>
            <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{tr("notifDigestTitle", locale)}</div>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{tr("notifDigestDesc", locale)}</div>
          </div>
        </div>
        {settings.daily_digest_enabled && (
          <div style={{ ...rowStyle, paddingLeft: "50px" }}>
            <span style={{ fontSize: "12px", color: "var(--tc-text)" }}>{tr("notifDigestTime", locale)}</span>
            <input type="time" value={settings.daily_digest_time}
              onChange={e => setSettings(s => ({ ...s, daily_digest_time: e.target.value }))}
              style={{ ...smallInput, width: "100px" }} />
          </div>
        )}
      </div>

      {/* Save */}
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <ChromeButton onClick={save} disabled={saving} variant="primary" style={{ minWidth: "140px" }}>
          {saving ? <Loader2 size={14} className="animate-spin" /> : saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
          {saved ? `${tr("save", locale)} ✓` : tr("save", locale)}
        </ChromeButton>
      </div>
    </ChromeInsetCard>
  );
}

// ═══════════════════════════════════════
// ANONYMIZER SECTION (scrollable)
// ═══════════════════════════════════════

const DEFAULT_ANONYMIZER_RULES = [
  { prefix: "IP", label: "Adresses IPv4 internes", pattern: "10.x.x.x, 172.16-31.x.x, 192.168.x.x", example: "192.168.1.42 → [IP-001]" },
  { prefix: "IP", label: "Adresses IPv6 ULA", pattern: "fd00::/8", example: "fd12:3456::1 → [IP-002]" },
  { prefix: "EMAIL", label: "Adresses email", pattern: "user@domain.tld", example: "admin@acme.fr → [EMAIL-001]" },
  { prefix: "HOST", label: "Noms d'hôtes internes", pattern: "*.internal, *.local, *.corp, *.lan", example: "dc01.ad.corp → [HOST-001]" },
  { prefix: "CRED", label: "Credentials (clé=valeur)", pattern: "password=, token=, api_key=, secret=", example: "password=s3cret → password=[CRED-001]" },
  { prefix: "SSHKEY", label: "Clés privées SSH/RSA/EC", pattern: "-----BEGIN * PRIVATE KEY-----", example: "Clé entière → [SSHKEY-001]" },
  { prefix: "AWSKEY", label: "Clés AWS (AKIA/ASIA)", pattern: "AKIA... / ASIA... (20 chars)", example: "AKIAIOSFODNN7EX → [AWSKEY-001]" },
  { prefix: "AZURECONN", label: "Azure Connection Strings", pattern: "AccountKey=, DefaultEndpointsProtocol=", example: "AccountKey=base64... → [AZURECONN-001]" },
  { prefix: "GCPKEY", label: "Clés GCP Service Account", pattern: '"type": "service_account"', example: "JSON SA détecté → [GCPKEY-001]" },
  { prefix: "PHONE", label: "Téléphones français", pattern: "06 xx xx xx xx, +33 x xx xx xx xx", example: "06 12 34 56 78 → [PHONE-001]" },
  { prefix: "SIRET", label: "SIRET (14 chiffres)", pattern: "xxx xxx xxx xxxxx", example: "123 456 789 00012 → [SIRET-001]" },
  { prefix: "SIREN", label: "SIREN (9 chiffres)", pattern: "xxx xxx xxx", example: "123 456 789 → [SIREN-001]" },
  { prefix: "MAC", label: "Adresses MAC (EUI-48)", pattern: "aa:bb:cc:dd:ee:ff", example: "00:1a:2b:3c:4d:5e → [MAC-001]" },
];

function DefaultRulesPanel() {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginBottom: "16px" }}>
      <button onClick={() => setOpen(!open)} style={{
        background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
        borderRadius: "var(--tc-radius-input)", padding: "8px 14px", cursor: "pointer",
        fontSize: "12px", fontWeight: 600, color: "var(--tc-text-sec)", fontFamily: "inherit",
        display: "flex", alignItems: "center", gap: "6px", width: "100%",
      }}>
        <Eye size={14} color="#d03020" />
        {open ? "Masquer" : "Voir"} les {DEFAULT_ANONYMIZER_RULES.length} règles par défaut
        <ChevronDown size={12} style={{ marginLeft: "auto", transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }} />
      </button>
      {open && (
        <div style={{ marginTop: "8px", display: "flex", flexDirection: "column", gap: "4px" }}>
          {DEFAULT_ANONYMIZER_RULES.map((rule, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: "10px",
              padding: "8px 12px", borderRadius: "var(--tc-radius-sm)",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
            }}>
              <span style={{
                fontSize: "8px", fontWeight: 800, padding: "2px 6px", borderRadius: "3px",
                background: "rgba(48,160,80,0.1)", color: "#30a050", fontFamily: "monospace",
                minWidth: "70px", textAlign: "center",
              }}>[{rule.prefix}]</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>{rule.label}</div>
                <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontFamily: "monospace" }}>{rule.pattern}</div>
              </div>
              <div style={{ fontSize: "10px", color: "var(--tc-text-faint)", fontFamily: "monospace", whiteSpace: "nowrap" }}>{rule.example}</div>
            </div>
          ))}
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", padding: "8px 0", lineHeight: 1.5 }}>
            Ces règles sont appliquées automatiquement avant tout envoi au LLM cloud.
            Les données originales ne quittent jamais le serveur — seuls les placeholders sont transmis.
            Le LLM répond avec les placeholders, ThreatClaw les remplace par les vraies valeurs localement.
          </div>
        </div>
      )}
    </div>
  );
}

function AnonymizerSection({ inputStyle, labelStyle }: { inputStyle: React.CSSProperties; labelStyle: React.CSSProperties }) {
  const locale = useLocale();
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
          <Shield size={18} color="#d03020" /> {tr("anonymization", locale)}
        </ChromeEmbossedText>
        <div style={{ fontSize: "13px", color: "var(--tc-text-muted)", marginBottom: "12px", lineHeight: 1.6 }}>
          <strong style={{ color: "var(--tc-text-sec)" }}>{tr("autoCategories", locale)}</strong> {tr("autoCategoriesDesc", locale)}
        </div>
        <DefaultRulesPanel />

        {/* Rules list - scrollable */}
        <div style={{ maxHeight: "400px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "8px" }}
          className="scrollbar-thin">
          {rules.length === 0 && (
            <div style={{ textAlign: "center", padding: "24px", color: "var(--tc-text-muted)", fontSize: "13px" }}>
              {tr("noCustomRules", locale)}
            </div>
          )}
          {rules.map(rule => (
            <div key={rule.id} style={{
              display: "flex", alignItems: "center", gap: "12px",
              padding: "12px 14px", borderRadius: "var(--tc-radius-md)",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
            }}>
              <Shield size={14} color="#30a050" />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)" }}>{rule.label}</div>
                <div style={{ fontSize: "11px", fontFamily: "monospace", color: "var(--tc-text-muted)" }}>
                  {rule.pattern} → [{rule.token_prefix}-001]
                </div>
              </div>
              <button onClick={() => deleteRule(rule.id)} style={{
                background: "rgba(208,48,32,0.06)", border: "1px solid var(--tc-red-border)",
                borderRadius: "var(--tc-radius-input)", cursor: "pointer", padding: "6px 8px", transition: "all 0.2s ease",
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
          <Plus size={16} color="#d03020" /> {tr("addRule", locale)}
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
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "6px", lineHeight: 1.5 }}>
              Exemples : mot exact (Projet-Neptune), insensible casse {"((?i)confidentiel)"}, pattern {"(SRV-\\d+ pour SRV-001, SRV-042...)"}
            </div>
          </div>
          <div style={{ display: "flex", gap: "12px", alignItems: "flex-end" }}>
            <div style={{ width: "140px" }}>
              <div style={labelStyle}>Préfixe</div>
              <input style={{ ...inputStyle, textTransform: "uppercase" }} value={newPrefix}
                onChange={e => setNewPrefix(e.target.value.toUpperCase())} />
            </div>
            <div style={{ flex: 1, fontSize: "12px", color: "var(--tc-text-muted)", paddingBottom: "12px" }}>
              → Le LLM verra [{newPrefix || "CUSTOM"}-001]
            </div>
            <ChromeButton onClick={addRule} disabled={adding || !newLabel || !newPattern} variant="primary">
              {adding ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              {tr("add", locale)}
            </ChromeButton>
          </div>
        </div>
      </ChromeInsetCard>
    </>
  );
}

// ── Company Profile Tab ──

function CompanyTab() {
  const locale = useLocale();
  const [profile, setProfile] = useState<any>({});
  const [networks, setNetworks] = useState<any[]>([]);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [newCidr, setNewCidr] = useState("");
  const [showSchedule, setShowSchedule] = useState(false);

  const DAYS = [
    { id: "mon", label: locale === "fr" ? "Lundi" : "Monday" }, { id: "tue", label: locale === "fr" ? "Mardi" : "Tuesday" }, { id: "wed", label: locale === "fr" ? "Mercredi" : "Wednesday" },
    { id: "thu", label: locale === "fr" ? "Jeudi" : "Thursday" }, { id: "fri", label: locale === "fr" ? "Vendredi" : "Friday" },
    { id: "sat", label: locale === "fr" ? "Samedi" : "Saturday" }, { id: "sun", label: locale === "fr" ? "Dimanche" : "Sunday" },
  ];

  const defaultSchedule: Record<string, { open: string; close: string; closed: boolean }> = {
    mon: { open: "08:00", close: "18:00", closed: false },
    tue: { open: "08:00", close: "18:00", closed: false },
    wed: { open: "08:00", close: "18:00", closed: false },
    thu: { open: "08:00", close: "18:00", closed: false },
    fri: { open: "08:00", close: "18:00", closed: false },
    sat: { open: "09:00", close: "12:00", closed: true },
    sun: { open: "09:00", close: "12:00", closed: true },
  };

  const [schedule, setSchedule] = useState(defaultSchedule);

  useEffect(() => {
    fetch("/api/tc/company").then(r => r.json()).then(d => {
      setProfile(d);
      // Parse work_days + hours into schedule
      const wd = d.work_days || ["mon", "tue", "wed", "thu", "fri"];
      const newSch = { ...defaultSchedule };
      DAYS.forEach(day => {
        newSch[day.id] = {
          open: d.business_hours_start || "08:00",
          close: d.business_hours_end || "18:00",
          closed: !wd.includes(day.id),
        };
      });
      setSchedule(newSch);
    }).catch(() => {});
    fetch("/api/tc/networks").then(r => r.json()).then(d => setNetworks(d.networks || [])).catch(() => {});
  }, []);

  const applyToAll = (open: string, close: string) => {
    setSchedule(s => {
      const n = { ...s };
      DAYS.forEach(d => { if (!n[d.id].closed) { n[d.id] = { ...n[d.id], open, close }; } });
      return n;
    });
  };

  const saveSchedule = () => {
    const workDays = DAYS.filter(d => !schedule[d.id].closed).map(d => d.id);
    const firstOpen = DAYS.find(d => !schedule[d.id].closed);
    setProfile((p: any) => ({
      ...p,
      work_days: workDays,
      business_hours: workDays.length === 7 ? "24x7" : "custom",
      business_hours_start: firstOpen ? schedule[firstOpen.id].open : "08:00",
      business_hours_end: firstOpen ? schedule[firstOpen.id].close : "18:00",
    }));
    setShowSchedule(false);
  };

  const handleSave = async () => {
    setSaving(true);
    await fetch("/api/tc/company", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(profile),
    });
    setSaving(false); setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const addNetwork = async () => {
    if (!newCidr.includes("/")) return;
    await fetch("/api/tc/networks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cidr: newCidr, label: "", zone: "lan" }) });
    setNewCidr("");
    const d = await fetch("/api/tc/networks").then(r => r.json());
    setNetworks(d.networks || []);
  };

  const deleteNetwork = async (id: number) => {
    await fetch(`/api/tc/networks/${id}`, { method: "DELETE" });
    setNetworks(nets => nets.filter(n => n.id !== id));
  };

  const inputStyle: React.CSSProperties = {
    width: "100%", padding: "8px 10px", fontSize: "11px", fontFamily: "inherit",
    background: "var(--tc-input)", border: "1px solid var(--tc-border)",
    borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)", outline: "none",
  };
  const labelStyle: React.CSSProperties = {
    fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)",
    textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "3px", display: "block",
  };

  return (
    <>
      <ChromeInsetCard>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "16px" }}>{tr("companyProfile", locale)}</ChromeEmbossedText>

        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div>
            <label style={labelStyle}>{tr("companyName", locale)}</label>
            <input value={profile.company_name || ""} onChange={e => setProfile((p: any) => ({ ...p, company_name: e.target.value }))} placeholder="CyberConsulting.fr" style={inputStyle} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
            <div>
              <label style={labelStyle}>{tr("sector", locale)}</label>
              <select value={profile.sector || "other"} onChange={e => setProfile((p: any) => ({ ...p, sector: e.target.value }))} style={inputStyle}>
                <option value="industry">{tr("sectorIndustry", locale)}</option>
                <option value="healthcare">{tr("sectorHealth", locale)}</option>
                <option value="finance">{tr("sectorFinance", locale)}</option>
                <option value="retail">{tr("sectorRetail", locale)}</option>
                <option value="government">{tr("sectorGov", locale)}</option>
                <option value="services">{tr("sectorServices", locale)}</option>
                <option value="transport">{tr("sectorTransport", locale)}</option>
                <option value="energy">{tr("sectorEnergy", locale)}</option>
                <option value="education">{tr("sectorEducation", locale)}</option>
                <option value="other">{tr("sectorOther", locale)}</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>{tr("companySize", locale)}</label>
              <select value={profile.company_size || "small"} onChange={e => setProfile((p: any) => ({ ...p, company_size: e.target.value }))} style={inputStyle}>
                <option value="micro">{tr("sizeMicro", locale)}</option>
                <option value="small">{tr("sizeSmall", locale)}</option>
                <option value="medium">{tr("sizeMedium", locale)}</option>
                <option value="large">{tr("sizeLarge", locale)}</option>
              </select>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
            <div>
              <label style={labelStyle}>Horaires d{"'"}activité</label>
              <button onClick={() => setShowSchedule(true)} style={{
                ...inputStyle, cursor: "pointer", textAlign: "left" as const,
                display: "flex", alignItems: "center", justifyContent: "space-between",
              }}>
                <span>{profile.business_hours === "24x7" ? "24h/7j" : profile.business_hours === "custom" ? "Personnalisé" : "Bureau (8h-18h)"}</span>
                <Settings size={12} color="var(--tc-text-muted)" />
              </button>
            </div>
            <div>
              <label style={labelStyle}>Zone géographique</label>
              <select value={profile.geo_scope || "france"} onChange={e => setProfile((p: any) => ({ ...p, geo_scope: e.target.value }))} style={inputStyle}>
                <option value="france">France uniquement</option>
                <option value="europe">Europe</option>
                <option value="international">International</option>
              </select>
            </div>
          </div>

          <div>
            <label style={labelStyle}>Systèmes critiques (séparés par des virgules)</label>
            <input value={(profile.critical_systems || []).join(", ")} onChange={e => setProfile((p: any) => ({ ...p, critical_systems: e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean) }))}
              placeholder="ERP, base clients, paye, site web" style={inputStyle} />
          </div>

          <div>
            <label style={labelStyle}>Sensibilité de la détection comportementale</label>
            <select value={profile.anomaly_sensitivity || "medium"} onChange={e => setProfile((p: any) => ({ ...p, anomaly_sensitivity: e.target.value }))} style={inputStyle}>
              <option value="low">Basse — moins d{"'"}alertes, plus de tolérance</option>
              <option value="medium">Moyenne — équilibre alertes / faux positifs</option>
              <option value="high">Haute — plus d{"'"}alertes, plus sensible aux écarts</option>
            </select>
          </div>

          <button onClick={handleSave} disabled={saving} style={{
            padding: "10px 20px", fontSize: "12px", fontWeight: 700, fontFamily: "inherit",
            cursor: "pointer", background: saved ? "var(--tc-green)" : "var(--tc-red)", color: "#fff",
            border: "none", borderRadius: "var(--tc-radius-md)", alignSelf: "flex-start",
            display: "flex", alignItems: "center", gap: "6px",
          }}>
            {saved ? tr("saved2", locale) : saving ? tr("saving2", locale) : tr("save", locale)}
          </button>
        </div>
      </ChromeInsetCard>

      <ChromeInsetCard style={{ marginTop: "16px" }}>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "12px" }}>{tr("internalNetworksLabel", locale)}</ChromeEmbossedText>
        <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>
          Déclarez vos plages réseau. ThreatClaw classifie les IPs (interne connu / inconnu / externe).
        </p>
        {networks.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "12px" }}>
            {networks.map((n: any) => (
              <div key={n.id} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "6px 10px", background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)" }}>
                <span style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--tc-text)", flex: 1 }}>{n.cidr}</span>
                <span style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>{n.label || n.zone}</span>
                <button onClick={() => deleteNetwork(n.id)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", fontSize: "14px" }}>×</button>
              </div>
            ))}
          </div>
        )}
        <div style={{ display: "flex", gap: "8px" }}>
          <input value={newCidr} onChange={e => setNewCidr(e.target.value)} placeholder="192.168.1.0/24" onKeyDown={e => e.key === "Enter" && addNetwork()} style={{ ...inputStyle, flex: 1 }} />
          <button onClick={addNetwork} style={{ padding: "8px 14px", fontSize: "11px", fontWeight: 600, fontFamily: "inherit", cursor: "pointer", background: "var(--tc-input)", color: "var(--tc-text-sec)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)" }}>{tr("add", locale)}</button>
        </div>
      </ChromeInsetCard>

      {/* ═══ Schedule Modal ═══ */}
      {showSchedule && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}
          onClick={e => { if (e.target === e.currentTarget) setShowSchedule(false); }}>
          <div style={{ background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "24px", width: "480px", maxHeight: "80vh", overflowY: "auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>{tr("businessHoursLabel", locale)}</h2>
              <button onClick={() => setShowSchedule(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)" }}><X size={16} /></button>
            </div>

            <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "16px" }}>
              La détection comportementale utilise ces horaires pour ajuster ses seuils. Une connexion en dehors des heures d{"'"}activité sera plus suspecte.
            </p>

            {/* Quick apply */}
            <div style={{ display: "flex", gap: "6px", marginBottom: "16px", flexWrap: "wrap" }}>
              <button onClick={() => applyToAll("08:00", "18:00")} style={{ ...inputStyle, width: "auto", padding: "4px 10px", fontSize: "9px", cursor: "pointer", fontWeight: 600 }}>8h-18h</button>
              <button onClick={() => applyToAll("09:00", "17:00")} style={{ ...inputStyle, width: "auto", padding: "4px 10px", fontSize: "9px", cursor: "pointer", fontWeight: 600 }}>9h-17h</button>
              <button onClick={() => { setSchedule(s => { const n = { ...s }; ["sat", "sun"].forEach(d => { n[d] = { ...n[d], closed: true }; }); return n; }); }} style={{ ...inputStyle, width: "auto", padding: "4px 10px", fontSize: "9px", cursor: "pointer", fontWeight: 600 }}>{locale === "fr" ? "Fermé le week-end" : "Closed on weekends"}</button>
              <button onClick={() => { setSchedule(s => { const n = { ...s }; DAYS.forEach(d => { n[d.id] = { open: "00:00", close: "23:59", closed: false }; }); return n; }); }} style={{ ...inputStyle, width: "auto", padding: "4px 10px", fontSize: "9px", cursor: "pointer", fontWeight: 600 }}>24/7</button>
            </div>

            {/* Per-day schedule */}
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {DAYS.map(day => (
                <div key={day.id} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "6px 10px", background: schedule[day.id].closed ? "var(--tc-input)" : "transparent", borderRadius: "var(--tc-radius-sm)", opacity: schedule[day.id].closed ? 0.5 : 1 }}>
                  <span style={{ width: "70px", fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>{day.label}</span>
                  <input type="checkbox" className="tc-toggle" checked={!schedule[day.id].closed}
                    onChange={() => setSchedule(s => ({ ...s, [day.id]: { ...s[day.id], closed: !s[day.id].closed } }))} />
                  {!schedule[day.id].closed ? (
                    <>
                      <input type="time" value={schedule[day.id].open} onChange={e => setSchedule(s => ({ ...s, [day.id]: { ...s[day.id], open: e.target.value } }))}
                        style={{ ...inputStyle, width: "100px", textAlign: "center" }} />
                      <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>à</span>
                      <input type="time" value={schedule[day.id].close} onChange={e => setSchedule(s => ({ ...s, [day.id]: { ...s[day.id], close: e.target.value } }))}
                        style={{ ...inputStyle, width: "100px", textAlign: "center" }} />
                    </>
                  ) : (
                    <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontStyle: "italic" }}>{tr("closed", locale)}</span>
                  )}
                </div>
              ))}
            </div>

            <button onClick={saveSchedule} style={{
              marginTop: "16px", padding: "10px 20px", fontSize: "12px", fontWeight: 700, fontFamily: "inherit",
              cursor: "pointer", background: "var(--tc-red)", color: "#fff",
              border: "none", borderRadius: "var(--tc-radius-md)", display: "flex", alignItems: "center", gap: "6px",
            }}>
              <CheckCircle2 size={14} /> {tr("apply", locale)}
            </button>
          </div>
        </div>
      )}
    </>
  );
}

// ── Log Sources Tab ──

function LogSourcesTab() {
  const locale = useLocale();
  const [stats, setStats] = useState<any>(null);
  const [expandedGuide, setExpandedGuide] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/logs/stats");
      setStats(await res.json());
    } catch {}
  }, []);

  useEffect(() => { loadStats(); }, [loadStats]);
  useEffect(() => { const i = setInterval(loadStats, 10000); return () => clearInterval(i); }, [loadStats]);

  const serverIp = typeof window !== "undefined" ? window.location.hostname : "YOUR_IP";
  const port = stats?.syslog_port || 514;
  const hasLogs = (stats?.today || 0) > 0;

  const testReception = async () => {
    setTesting(true); setTestResult(null);
    await new Promise(r => setTimeout(r, 5000));
    await loadStats(); setTesting(false);
    setTestResult(locale === "fr" ? "Vérification terminée. Consultez le compteur ci-dessus." : "Check complete. See the counter above.");
    setTimeout(() => setTestResult(null), 5000);
  };

  const guides = [
    { id: "linux", title: "Linux (rsyslog)", steps: [
      { fr: "Ouvrez un terminal sur votre serveur Linux", en: "Open a terminal on your Linux server" },
      { fr: "Exécutez cette commande :", en: "Run this command:", cmd: `echo "*.* @@${serverIp}:${port}" | sudo tee /etc/rsyslog.d/threatclaw.conf && sudo systemctl restart rsyslog` },
      { fr: "Testez avec :", en: "Test with:", cmd: `logger -t threatclaw-test "Test log from $(hostname)"` },
    ]},
    { id: "windows", title: "Windows (NXLog)", steps: [
      { fr: "Téléchargez NXLog Community Edition (gratuit)", en: "Download NXLog Community Edition (free)", cmd: "https://nxlog.co/downloads/nxlog-ce" },
      { fr: "Ajoutez dans la config NXLog :", en: "Add to NXLog config:", cmd: `<Output out>\n  Module om_tcp\n  Host ${serverIp}\n  Port ${port}\n</Output>` },
      { fr: "Redémarrez le service NXLog", en: "Restart the NXLog service" },
    ]},
    { id: "firewall", title: "Firewall (pfSense / FortiGate)", steps: [
      { fr: "pfSense : Status > System Logs > Settings > Enable Remote Logging", en: "pfSense: Status > System Logs > Settings > Enable Remote Logging" },
      { fr: "FortiGate :", en: "FortiGate:", cmd: `config log syslogd setting\n  set status enable\n  set server "${serverIp}"\n  set port ${port}\nend` },
      { fr: `Entrez l'IP : ${serverIp}:${port}`, en: `Enter IP: ${serverIp}:${port}` },
    ]},
    { id: "docker", title: "Docker", steps: [
      { fr: "Ajoutez le flag :", en: "Add the flag:", cmd: `docker run --log-driver=fluentd --log-opt fluentd-address=${serverIp}:24224 your-image` },
      { fr: "Ou dans docker-compose.yml :", en: "Or in docker-compose.yml:", cmd: `logging:\n  driver: fluentd\n  options:\n    fluentd-address: "${serverIp}:24224"` },
    ]},
  ];

  return (
    <ChromeInsetCard>
      <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "16px" }}>
        {locale === "fr" ? "Sources de logs" : "Log Sources"}
      </ChromeEmbossedText>

      {/* Server address */}
      <div style={{ padding: "14px 16px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-input)", border: "1px solid var(--tc-border)", marginBottom: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "4px" }}>
              {locale === "fr" ? "ThreatClaw écoute sur" : "ThreatClaw listens on"}
            </div>
            <div style={{ fontSize: "14px", fontWeight: 800, fontFamily: "monospace", color: "var(--tc-text)" }}>
              {serverIp}:{port} <span style={{ fontSize: "10px", fontWeight: 400, color: "var(--tc-text-muted)" }}>TCP + UDP</span>
            </div>
          </div>
          <button onClick={() => navigator.clipboard.writeText(`${serverIp}:${port}`)} className="tc-btn-embossed" style={{ fontSize: "10px", padding: "6px 12px" }}>
            {locale === "fr" ? "Copier" : "Copy"}
          </button>
        </div>
        <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "8px" }}>
          {locale === "fr" ? "Tout équipement compatible syslog peut envoyer ses logs à cette adresse." : "Any syslog-compatible device can send logs to this address."}
        </div>
      </div>

      {/* Live status */}
      <div style={{
        padding: "14px 16px", borderRadius: "var(--tc-radius-sm)", marginBottom: "16px",
        background: hasLogs ? "rgba(48,160,80,0.06)" : "rgba(208,144,32,0.06)",
        border: hasLogs ? "1px solid rgba(48,160,80,0.15)" : "1px solid rgba(208,144,32,0.15)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            {hasLogs ? <CheckCircle2 size={14} color="#30a050" /> : <AlertTriangle size={14} color="var(--tc-amber)" />}
            <span style={{ fontSize: "13px", fontWeight: 700, color: hasLogs ? "#30a050" : "var(--tc-amber)" }}>
              {hasLogs ? `${stats.today.toLocaleString()} ${locale === "fr" ? "logs reçus aujourd'hui" : "logs received today"}` : (locale === "fr" ? "Aucun log reçu" : "No logs received")}
            </span>
          </div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "4px", display: "flex", gap: "12px" }}>
            {stats?.last_received && <span>{locale === "fr" ? "Dernier" : "Last"}: {new Date(stats.last_received).toLocaleString()}</span>}
            {stats?.sources_count > 0 && <span>{stats.sources_count} source(s)</span>}
            {stats?.total_30d > 0 && <span>{stats.total_30d.toLocaleString()} / 30{locale === "fr" ? "j" : "d"}</span>}
          </div>
        </div>
        <button onClick={testReception} disabled={testing} className="tc-btn-embossed" style={{ fontSize: "10px", padding: "6px 12px" }}>
          {testing ? <><Loader2 size={10} className="animate-spin" /></> : <><RefreshCw size={10} /> {locale === "fr" ? "Vérifier" : "Check"}</>}
        </button>
      </div>

      {testResult && <div style={{ fontSize: "10px", color: "var(--tc-green)", marginBottom: "12px", padding: "6px 10px", borderRadius: "var(--tc-radius-sm)", background: "rgba(48,160,80,0.06)" }}>{testResult}</div>}

      {/* Guides */}
      <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "10px" }}>
        {locale === "fr" ? "Guides de connexion" : "Connection guides"}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
        {guides.map(g => {
          const isExp = expandedGuide === g.id;
          return (
            <div key={g.id} style={{ borderRadius: "var(--tc-radius-sm)", background: "var(--tc-input)", border: isExp ? "1px solid var(--tc-border-accent)" : "1px solid var(--tc-border)", overflow: "hidden" }}>
              <button onClick={() => setExpandedGuide(isExp ? null : g.id)} style={{
                width: "100%", display: "flex", alignItems: "center", gap: "8px", padding: "10px 12px",
                background: "transparent", border: "none", cursor: "pointer", color: "var(--tc-text)",
                fontSize: "12px", fontWeight: 600, fontFamily: "inherit", textAlign: "left",
              }}>
                {isExp ? <ChevronDown size={12} color="var(--tc-text-muted)" /> : <ChevronRight size={12} color="var(--tc-text-muted)" />}
                {g.title}
              </button>
              {isExp && (
                <div style={{ padding: "0 12px 12px", borderTop: "1px solid var(--tc-border)" }}>
                  {g.steps.map((s, i) => (
                    <div key={i} style={{ marginTop: "10px" }}>
                      <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", marginBottom: "4px" }}>
                        {i + 1}. {locale === "fr" ? s.fr : s.en}
                      </div>
                      {s.cmd && (
                        <div style={{ position: "relative", padding: "8px 10px", borderRadius: "var(--tc-radius-sm)", background: "rgba(0,0,0,0.3)", fontFamily: "monospace", fontSize: "10px", color: "var(--tc-green)", whiteSpace: "pre-wrap", wordBreak: "break-all", border: "1px solid var(--tc-border)" }}>
                          {s.cmd}
                          <button onClick={() => navigator.clipboard.writeText(s.cmd!)} style={{ position: "absolute", top: "4px", right: "4px", padding: "2px 6px", fontSize: "8px", fontWeight: 700, background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", borderRadius: "4px", color: "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit" }}>
                            {locale === "fr" ? "Copier" : "Copy"}
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </ChromeInsetCard>
  );
}

// ── System Logs Tab ──

function LiveLogsTab() {
  const [events, setEvents] = useState<any[]>([]);
  const [paused, setPaused] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filter, setFilter] = useState("all");

  const loadLogs = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/system-logs?limit=100");
      const d = await res.json();
      setEvents(d.events || []);
      setPaused(d.paused || false);
    } catch {}
  }, []);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(loadLogs, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadLogs]);

  const filtered = filter === "all" ? events : events.filter(e => e.type === filter);

  const typeColors: Record<string, string> = {
    audit: "var(--tc-blue)",
    auth: "#a040d0",
    notification: "var(--tc-amber)",
  };

  const typeLabels: Record<string, string> = {
    audit: "BOT",
    auth: "AUTH",
    notification: "NOTIF",
  };

  const formatTime = (ts: string) => {
    if (!ts) return "";
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch { return ts; }
  };

  const formatEvent = (e: any) => {
    if (e.type === "audit") return `${e.action} ${e.target || ""} ${e.success === false ? "FAILED" : ""}`.trim();
    if (e.type === "auth") return `${e.event} ${e.email} ${e.ip || ""}`.trim();
    if (e.type === "notification") return `${e.level} → ${e.channel}`.trim();
    return e.key || "?";
  };

  return (
    <ChromeInsetCard>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, margin: 0 }}>Logs système</ChromeEmbossedText>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {paused && <span style={{ fontSize: "10px", fontWeight: 700, color: "#d03020", padding: "2px 8px", borderRadius: "4px", background: "rgba(208,48,32,0.1)" }}>PAUSE</span>}
          <label style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px", color: "var(--tc-text-muted)", cursor: "pointer" }}>
            <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} style={{ accentColor: "#30a050" }} />
            Auto (5s)
          </label>
          <button className="tc-btn-embossed" onClick={loadLogs} style={{ fontSize: "10px", padding: "4px 10px" }}>
            <RefreshCw size={10} />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "12px" }}>
        {[
          { key: "all", label: "Tous" },
          { key: "audit", label: "Bot / Actions" },
          { key: "auth", label: "Authentification" },
          { key: "notification", label: "Notifications" },
        ].map(f => (
          <button key={f.key} onClick={() => setFilter(f.key)} style={{
            padding: "4px 10px", fontSize: "10px", fontWeight: 600, borderRadius: "6px", cursor: "pointer",
            background: filter === f.key ? "var(--tc-surface-alt)" : "transparent",
            border: filter === f.key ? "1px solid var(--tc-border)" : "1px solid transparent",
            color: filter === f.key ? "var(--tc-text)" : "var(--tc-text-muted)",
          }}>{f.label}</button>
        ))}
      </div>

      {/* Log entries */}
      <div style={{
        maxHeight: "400px", overflow: "auto", borderRadius: "var(--tc-radius-sm)",
        background: "rgba(0,0,0,0.3)", border: "1px solid var(--tc-border)",
        fontFamily: "monospace", fontSize: "11px",
      }}>
        {filtered.length === 0 && (
          <div style={{ padding: "20px", textAlign: "center", color: "var(--tc-text-faint)" }}>
            Aucun événement
          </div>
        )}
        {filtered.map((e, i) => (
          <div key={i} style={{
            display: "flex", gap: "8px", padding: "4px 10px",
            borderBottom: "1px solid rgba(255,255,255,0.03)",
            color: "var(--tc-text-sec)",
          }}>
            <span style={{ color: "var(--tc-text-muted)", minWidth: "60px", flexShrink: 0 }}>{formatTime(e.timestamp)}</span>
            <span style={{
              color: typeColors[e.type] || "var(--tc-text-muted)",
              fontWeight: 700, minWidth: "45px", flexShrink: 0, fontSize: "9px",
              padding: "1px 0",
            }}>{typeLabels[e.type] || e.type}</span>
            <span style={{ color: e.type === "auth" && e.event?.includes("failed") ? "#d03020" : "var(--tc-text-sec)" }}>
              {formatEvent(e)}
            </span>
          </div>
        ))}
      </div>

      <div style={{ marginTop: "8px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
        {filtered.length} événement(s) · Rafraîchissement {autoRefresh ? "automatique 5s" : "manuel"}
      </div>
    </ChromeInsetCard>
  );
}

function RetentionTab() {
  const [retention, setRetention] = useState({ logs: 90, alerts: 365, findings: 0, audit: 0 });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetch("/api/tc/config?key=_retention").then(r => r.json()).then(d => {
      if (d._retention) setRetention(prev => ({ ...prev, ...d._retention }));
    }).catch(() => {});
  }, []);

  const save = async () => {
    await fetch("/api/tc/config", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: "_retention", value: retention }),
    });
    setSaved(true); setTimeout(() => setSaved(false), 2000);
  };

  const items = [
    { key: "logs" as const, label: "Logs réseau (syslog, Zeek, Suricata)", size: "~9 GB / 100K logs/jour", legal: "NIS2 : 6 mois recommandé", unit: "jours" },
    { key: "alerts" as const, label: "Alertes de sécurité (Sigma)", size: "~500 MB / 10K alertes/jour", legal: "NIS2 : conservation obligatoire", unit: "jours" },
    { key: "findings" as const, label: "Findings (vulnérabilités)", size: "~100 MB / an", legal: "Preuve d'audit", unit: "jours" },
    { key: "audit" as const, label: "Journal d'audit (actions agent)", size: "~50 MB / an", legal: "NIS2 : preuve légale", unit: "jours" },
  ];

  return (
    <ChromeInsetCard>
      <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "12px" }}>Rétention des données</ChromeEmbossedText>
      <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "16px" }}>
        Définissez combien de temps ThreatClaw conserve les données. 0 = illimité. NIS2 impose un minimum de 6 mois pour les logs.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {items.map(item => (
          <div key={item.key} style={{ display: "flex", alignItems: "center", gap: "12px", padding: "10px 12px", background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)" }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>{item.label}</div>
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{item.size} · {item.legal}</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <input type="number" min={0} value={retention[item.key]} onChange={e => setRetention(p => ({ ...p, [item.key]: parseInt(e.target.value) || 0 }))}
                style={{ width: "60px", padding: "4px 6px", fontSize: "12px", fontWeight: 700, textAlign: "right",
                  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                  color: "var(--tc-blue)", outline: "none" }} />
              <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", minWidth: "30px" }}>{retention[item.key] === 0 ? "∞" : item.unit}</span>
            </div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "12px" }}>
        <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontStyle: "italic" }}>
          Nettoyage automatique chaque nuit à 03h00.
        </div>
        <button className="tc-btn-embossed" onClick={save} style={{ fontSize: "11px", padding: "6px 14px" }}>
          {saved ? "✓ Saved" : "Save"}
        </button>
      </div>
    </ChromeInsetCard>
  );
}

function BackupTab() {
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<string | null>(null);
  const [versionInfo, setVersionInfo] = useState<any>(null);
  const [exportMode, setExportMode] = useState<"light" | "full">("light");

  useEffect(() => {
    fetch("/api/tc/version/check", { signal: AbortSignal.timeout(8000) })
      .then(r => r.json()).then(d => setVersionInfo(d)).catch(() => {});
  }, []);

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await fetch(`/api/tc/backup/export?mode=${exportMode}`);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `threatclaw-backup-${new Date().toISOString().slice(0, 10)}-${exportMode}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert("Erreur export: " + e.message);
    }
    setExporting(false);
  };

  const handleImport = async () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e: any) => {
      const file = e.target.files?.[0];
      if (!file) return;
      setImporting(true);
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const res = await fetch("/api/tc/backup/import", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
        });
        const result = await res.json();
        setImportResult(`Import réussi : ${(result.sections || []).join(", ")}`);
      } catch (err: any) {
        setImportResult("Erreur: " + err.message);
      }
      setImporting(false);
    };
    input.click();
  };

  return (
    <>
      <ChromeInsetCard>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "12px" }}>Sauvegarde</ChromeEmbossedText>
        <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "16px" }}>
          Exportez votre configuration pour la restaurer sur un nouveau serveur ou en cas de réinstallation.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "16px" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", fontSize: "12px" }}>
            <input type="radio" name="exportMode" checked={exportMode === "light"} onChange={() => setExportMode("light")} />
            <div>
              <div style={{ fontWeight: 700, color: "var(--tc-text)" }}>Export léger (~50 KB)</div>
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>Configuration, assets, réseaux, skills, profil entreprise</div>
            </div>
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", fontSize: "12px" }}>
            <input type="radio" name="exportMode" checked={exportMode === "full"} onChange={() => setExportMode("full")} />
            <div>
              <div style={{ fontWeight: 700, color: "var(--tc-text)" }}>Export complet (taille variable)</div>
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>Tout le léger + alertes + findings + historique (pour migration complète)</div>
            </div>
          </label>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          <button onClick={handleExport} disabled={exporting} style={{
            padding: "10px 16px", fontSize: "12px", fontWeight: 700, fontFamily: "inherit",
            cursor: "pointer", background: "var(--tc-red)", color: "#fff",
            border: "none", borderRadius: "var(--tc-radius-md)", display: "flex", alignItems: "center", gap: "6px",
          }}>
            {exporting ? "Export en cours..." : "Exporter"}
          </button>
          <button onClick={handleImport} disabled={importing} style={{
            padding: "10px 16px", fontSize: "12px", fontWeight: 700, fontFamily: "inherit",
            cursor: "pointer", background: "var(--tc-input)", color: "var(--tc-text-sec)",
            border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", display: "flex", alignItems: "center", gap: "6px",
          }}>
            {importing ? "Import en cours..." : "Importer un fichier"}
          </button>
        </div>

        {importResult && (
          <div style={{ marginTop: "10px", padding: "8px 12px", borderRadius: "var(--tc-radius-sm)",
            background: importResult.startsWith("Erreur") ? "rgba(208,48,32,0.08)" : "rgba(48,160,80,0.08)",
            color: importResult.startsWith("Erreur") ? "#d03020" : "#30a050", fontSize: "11px" }}>
            {importResult}
          </div>
        )}
      </ChromeInsetCard>

      {/* Auto backups section */}
      <AutoBackupSection />

      <ChromeInsetCard style={{ marginTop: "16px" }}>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "12px" }}>Mises à jour</ChromeEmbossedText>

        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "12px" }}>
          <div style={{ fontSize: "12px", color: "var(--tc-text)" }}>
            Version actuelle : <span style={{ fontWeight: 700, fontFamily: "monospace" }}>{versionInfo?.current || "2.0.0-beta"}</span>
          </div>
          {versionInfo?.update_available && (
            <span style={{ fontSize: "10px", padding: "2px 8px", borderRadius: "var(--tc-radius-sm)",
              background: "rgba(208,48,32,0.08)", color: "#d03020", fontWeight: 700 }}>
              Nouvelle version : {versionInfo.latest}
            </span>
          )}
          {versionInfo && !versionInfo.update_available && (
            <span style={{ fontSize: "10px", padding: "2px 8px", borderRadius: "var(--tc-radius-sm)",
              background: "rgba(48,160,80,0.08)", color: "#30a050", fontWeight: 700 }}>
              À jour
            </span>
          )}
        </div>

        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", padding: "10px", background: "var(--tc-input)",
          borderRadius: "var(--tc-radius-sm)", fontFamily: "monospace", lineHeight: 1.8 }}>
          # Pour mettre à jour (Docker) :<br/>
          cd /opt/threatclaw<br/>
          docker compose pull<br/>
          docker compose up -d<br/>
          <br/>
          # Pour mettre à jour (binaire) :<br/>
          git pull origin main<br/>
          cargo build --release<br/>
          systemctl restart threatclaw
        </div>
      </ChromeInsetCard>
    </>
  );
}

// ── Auto backup section: schedule, retention, list, manual trigger ──

interface BackupInfo { name: string; size_bytes: number; created_at: string; }
interface BackupSettings {
  auto_enabled: boolean;
  auto_time: string;
  retention_count: number;
  external_path: string;
}

function AutoBackupSection() {
  const [settings, setSettings] = useState<BackupSettings>({
    auto_enabled: true,
    auto_time: "02:00",
    retention_count: 7,
    external_path: "",
  });
  const [backups, setBackups] = useState<BackupInfo[]>([]);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const loadBackups = () => {
    fetch("/api/tc/backups").then(r => r.json()).then(d => setBackups(d.backups || [])).catch(() => {});
  };

  useEffect(() => {
    fetch("/api/tc/backups/settings").then(r => r.json()).then(d => {
      if (d.auto_enabled !== undefined) setSettings(d);
    }).catch(() => {});
    loadBackups();
  }, []);

  const saveSettings = async () => {
    setSaving(true);
    try {
      await fetch("/api/tc/backups/settings", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: any) {
      setMessage("Erreur enregistrement: " + e.message);
    }
    setSaving(false);
  };

  const createNow = async () => {
    setCreating(true);
    setMessage(null);
    try {
      const res = await fetch("/api/tc/backups/create", { method: "POST" });
      if (res.ok) {
        const info = await res.json();
        setMessage(`Sauvegarde créée : ${info.name} (${(info.size_bytes / 1024).toFixed(0)} KB)`);
        loadBackups();
      } else {
        const err = await res.text();
        setMessage("Erreur création: " + err);
      }
    } catch (e: any) {
      setMessage("Erreur création: " + e.message);
    }
    setCreating(false);
  };

  const downloadBackup = (name: string) => {
    const a = document.createElement("a");
    a.href = `/api/tc/backups/download/${encodeURIComponent(name)}`;
    a.download = name;
    a.click();
  };

  const deleteBackup = async (name: string) => {
    if (!confirm(`Supprimer la sauvegarde ${name} ?`)) return;
    try {
      await fetch(`/api/tc/backups/${encodeURIComponent(name)}`, { method: "DELETE" });
      loadBackups();
    } catch (e: any) {
      setMessage("Erreur suppression: " + e.message);
    }
  };

  const fmtSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };
  const fmtDate = (iso: string) => {
    try { return new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" }); }
    catch { return iso; }
  };

  return (
    <ChromeInsetCard style={{ marginTop: "16px" }}>
      <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 800, marginBottom: "12px" }}>Sauvegardes automatiques</ChromeEmbossedText>
      <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "16px" }}>
        Sauvegarde quotidienne complète de la base : config, assets, incidents, alertes, ML scores. Stockée dans <code style={{ fontFamily: "monospace", fontSize: "10px" }}>/app/data/backups</code> par défaut. Pour un stockage externe, montez un volume Docker vers ce chemin.
      </p>

      {/* Settings form */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "16px" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "var(--tc-text)", cursor: "pointer" }}>
          <input type="checkbox" checked={settings.auto_enabled}
            onChange={e => setSettings(s => ({ ...s, auto_enabled: e.target.checked }))} />
          Activer la sauvegarde quotidienne
        </label>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px" }}>
          <span style={{ color: "var(--tc-text-muted)" }}>Heure (UTC) :</span>
          <input type="time" value={settings.auto_time}
            onChange={e => setSettings(s => ({ ...s, auto_time: e.target.value }))}
            style={{ padding: "4px 8px", fontSize: "12px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)" }} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px" }}>
          <span style={{ color: "var(--tc-text-muted)" }}>Rétention :</span>
          <input type="number" min={1} max={90} value={settings.retention_count}
            onChange={e => setSettings(s => ({ ...s, retention_count: parseInt(e.target.value) || 7 }))}
            style={{ padding: "4px 8px", fontSize: "12px", width: "60px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)" }} />
          <span style={{ color: "var(--tc-text-muted)" }}>sauvegardes</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", gridColumn: "1 / -1" }}>
          <span style={{ color: "var(--tc-text-muted)", whiteSpace: "nowrap" }}>Chemin externe (optionnel) :</span>
          <input type="text" value={settings.external_path} placeholder="/mnt/nas/threatclaw-backups"
            onChange={e => setSettings(s => ({ ...s, external_path: e.target.value }))}
            style={{ flex: 1, padding: "4px 8px", fontSize: "11px", fontFamily: "monospace", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)" }} />
        </div>
      </div>

      <div style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
        <button onClick={saveSettings} disabled={saving} style={{
          padding: "8px 14px", fontSize: "11px", fontWeight: 700, fontFamily: "inherit",
          cursor: "pointer", background: saved ? "#30a050" : "var(--tc-red)", color: "#fff",
          border: "none", borderRadius: "var(--tc-radius-sm)",
        }}>
          {saving ? "..." : saved ? "Enregistré ✓" : "Enregistrer les paramètres"}
        </button>
        <button onClick={createNow} disabled={creating} style={{
          padding: "8px 14px", fontSize: "11px", fontWeight: 700, fontFamily: "inherit",
          cursor: "pointer", background: "var(--tc-input)", color: "var(--tc-text-sec)",
          border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
        }}>
          {creating ? "Création..." : "Lancer une sauvegarde maintenant"}
        </button>
      </div>

      {message && (
        <div style={{ padding: "8px 12px", borderRadius: "var(--tc-radius-sm)", marginBottom: "12px",
          background: message.startsWith("Erreur") ? "rgba(208,48,32,0.08)" : "rgba(48,160,80,0.08)",
          color: message.startsWith("Erreur") ? "#d03020" : "#30a050", fontSize: "11px" }}>
          {message}
        </div>
      )}

      {/* Backup list */}
      <div style={{ marginTop: "12px" }}>
        <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "8px" }}>
          Sauvegardes existantes ({backups.length})
        </div>
        {backups.length === 0 ? (
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", padding: "12px", textAlign: "center", background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)" }}>
            Aucune sauvegarde pour le moment. Lancez-en une manuellement ou attendez l'heure programmée.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "240px", overflowY: "auto" }}>
            {backups.map(b => (
              <div key={b.name} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 12px",
                background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)", fontSize: "11px" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: "monospace", color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{b.name}</div>
                  <div style={{ color: "var(--tc-text-muted)", fontSize: "10px" }}>{fmtDate(b.created_at)}{fmtSize(b.size_bytes)}</div>
                </div>
                <button onClick={() => downloadBackup(b.name)} style={{
                  padding: "4px 10px", fontSize: "10px", fontWeight: 700, cursor: "pointer",
                  background: "var(--tc-red)", color: "#fff", border: "none", borderRadius: "var(--tc-radius-sm)",
                }}>Télécharger</button>
                <button onClick={() => deleteBackup(b.name)} style={{
                  padding: "4px 10px", fontSize: "10px", fontWeight: 700, cursor: "pointer",
                  background: "transparent", color: "var(--tc-text-muted)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                }}>Supprimer</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </ChromeInsetCard>
  );
}

"use client";

import React, { useState, useEffect } from "react";
import {
  Shield, ChevronRight, ChevronLeft, Cpu, Link2, ShieldCheck, Calendar,
  CheckCircle2, Eye, Bell, ShieldAlert, Zap, MessageSquare, Mail, Server,
  Check, Loader2, Wifi, AlertTriangle, Puzzle, Cloud, Lock, X,
} from "lucide-react";

const STEPS = [
  { id: "welcome", label: "Bienvenue" },
  { id: "company", label: "Entreprise" },
  { id: "llm-primary", label: "IA Principale" },
  { id: "llm-cloud", label: "IA de secours" },
  { id: "communication", label: "Communication" },
  { id: "security", label: "Sécurité" },
  { id: "confirm", label: "Lancement" },
];

interface PrimaryLlm {
  backend: string;
  url: string;
  model: string;
  apiKey: string;
  connected: boolean;
  testing: boolean;
  models: string[];
  detectedRam: number;
  recommendedModel: string;
}

interface CloudLlm {
  enabled: boolean;
  backend: string;
  model: string;
  baseUrl: string;
  apiKey: string;
  escalation: "never" | "anonymized" | "direct";
}

interface CommChannel {
  enabled: boolean;
  [key: string]: string | boolean;
}

interface ScheduleItem {
  enabled: boolean;
  label: string;
  description: string;
  default: string;
  cron: string;
}

// ── Shared inline styles (tc-* variables for dark/light compat) ──

const cardStyle: React.CSSProperties = {
  background: "var(--tc-surface-alt)",
  border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)",
  padding: "20px",
};

const cardSmStyle: React.CSSProperties = {
  background: "var(--tc-surface-alt)",
  border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)",
  padding: "10px 12px",
};

const btnPrimary: React.CSSProperties = {
  background: "var(--tc-red)", color: "#fff", border: "none", borderRadius: "var(--tc-radius-md)",
  padding: "10px 20px", fontSize: "12px", fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
  display: "inline-flex", alignItems: "center", gap: "6px", transition: "opacity 0.2s",
};

const btnSecondary: React.CSSProperties = {
  background: "var(--tc-input)", color: "var(--tc-text-sec)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)", padding: "8px 14px", fontSize: "11px", fontWeight: 600,
  cursor: "pointer", fontFamily: "inherit", display: "inline-flex", alignItems: "center", gap: "4px",
};

const inputStyle: React.CSSProperties = {
  width: "100%", padding: "8px 10px", fontSize: "11px", fontFamily: "inherit",
  background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
  color: "var(--tc-text)", outline: "none",
};

const labelStyle: React.CSSProperties = {
  fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)",
  textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "3px", display: "block",
};

export default function SetupWizard() {
  const [step, setStep] = useState(0);

  const [company, setCompany] = useState({
    company_name: "", sector: "other", company_size: "small",
    business_hours: "office", business_hours_start: "08:00", business_hours_end: "18:00",
    geo_scope: "france",
    internal_networks: "192.168.1.0/24",
  });

  const [primary, setPrimary] = useState<PrimaryLlm>({
    backend: "ollama",
    url: "http://localhost:11434",
    model: "",
    apiKey: "",
    connected: false,
    testing: false,
    models: [],
    detectedRam: 0,
    recommendedModel: "",
  });
  const [anonymizePrimary, setAnonymizePrimary] = useState(false);

  const [cloud, setCloud] = useState<CloudLlm>({
    enabled: false,
    backend: "anthropic",
    model: "claude-sonnet-4-20250514",
    baseUrl: "",
    apiKey: "",
    escalation: "anonymized",
  });

  const [channels, setChannels] = useState<Record<string, CommChannel>>({
    slack: { enabled: false, botToken: "", signingSecret: "" },
    telegram: { enabled: false, botToken: "", botUsername: "" },
    discord: { enabled: false, botToken: "", publicKey: "" },
    whatsapp: { enabled: false, accessToken: "", phoneNumberId: "" },
    signal: { enabled: false, httpUrl: "http://localhost:8080", account: "" },
    email: { enabled: false, host: "", port: "587", from: "", to: "" },
  });

  const [permLevel, setPermLevel] = useState("ALERT_ONLY");

  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [channelTest, setChannelTest] = useState<Record<string, { testing: boolean; result?: { ok: boolean; error?: string; username?: string; team?: string } }>>({});

  const testChannel = async (channelKey: string) => {
    const ch = channels[channelKey];
    const token = (ch.botToken || ch.accessToken || "") as string;
    setChannelTest(p => ({ ...p, [channelKey]: { testing: true } }));
    try {
      const res = await fetch("/api/tc/config/test-channel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: channelKey, token }),
      });
      const data = await res.json();
      setChannelTest(p => ({ ...p, [channelKey]: { testing: false, result: data } }));
    } catch {
      setChannelTest(p => ({ ...p, [channelKey]: { testing: false, result: { ok: false, error: "Connection failed" } } }));
    }
  };

  useEffect(() => {
    if (typeof navigator !== "undefined" && "deviceMemory" in navigator) {
      const ram = (navigator as Record<string, unknown>).deviceMemory as number;
      const recommended = ram <= 8 ? "qwen3:8b" : ram <= 16 ? "qwen3:14b" : ram <= 32 ? "qwen3:14b" : "qwen3:32b";
      setPrimary(p => ({ ...p, detectedRam: ram, recommendedModel: recommended }));
    }
  }, []);

  const testOllamaConnection = async () => {
    setPrimary(p => ({ ...p, testing: true, connected: false, models: [] }));
    try {
      const res = await fetch(`/api/ollama?url=${encodeURIComponent(primary.url)}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      const models = (data.models || []).map((m: { name: string }) => m.name);
      setPrimary(p => ({ ...p, testing: false, connected: true, models, model: p.model || models[0] || "" }));
    } catch {
      setPrimary(p => ({ ...p, testing: false, connected: false, models: [] }));
    }
  };

  const skipOnboarding = () => {
    localStorage.setItem("threatclaw_onboarded", "true");
    window.location.href = "/";
  };

  const handleSave = async () => {
    setSaving(true);

    // Save company profile
    try {
      await fetch("/api/tc/company", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company_name: company.company_name, sector: company.sector,
          company_size: company.company_size, business_hours: company.business_hours,
          geo_scope: company.geo_scope,
          allowed_countries: company.geo_scope === "france" ? ["FR"] : company.geo_scope === "europe" ? ["FR","DE","ES","IT","BE","NL","CH","AT","PT","LU"] : [],
        }),
      });
      // Save internal networks
      for (const line of company.internal_networks.split("\n")) {
        const cidr = line.trim();
        if (cidr && cidr.includes("/")) {
          await fetch("/api/tc/networks", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cidr, label: "Auto-config", zone: "lan" }),
          });
        }
      }
    } catch { /* non-blocking */ }

    const config = {
      llm: { backend: primary.backend, url: primary.url, model: primary.model, apiKey: primary.apiKey },
      anonymize_primary: anonymizePrimary,
      cloud: cloud.enabled ? { backend: cloud.backend, model: cloud.model, baseUrl: cloud.baseUrl, apiKey: cloud.apiKey, escalation: cloud.escalation } : null,
      channels,
      permissions: permLevel,
      general: { instanceName: company.company_name || "threatclaw", language: "fr" },
    };
    try {
      const res = await fetch("/api/tc/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(config) });
      const data = await res.json();
      if (data.status === "saved") {
        localStorage.setItem("threatclaw_onboarded", "true");
        setSaving(false);
        setSaved(true);
      } else {
        // Fallback
        localStorage.setItem("threatclaw_config", JSON.stringify(config));
        localStorage.setItem("threatclaw_onboarded", "true");
        setSaving(false);
        setSaved(true);
      }
    } catch {
      localStorage.setItem("threatclaw_config", JSON.stringify(config));
      localStorage.setItem("threatclaw_onboarded", "true");
      setSaving(false);
      setSaved(true);
    }
  };

  const next = () => setStep(s => Math.min(s + 1, STEPS.length - 1));
  const prev = () => setStep(s => Math.max(s - 1, 0));

  const permLevels = [
    { id: "READ_ONLY", icon: Eye, label: "Observation", desc: "Observation uniquement — aucune action", color: "var(--tc-blue)" },
    { id: "ALERT_ONLY", icon: Bell, label: "Alertes", desc: "Alertes sans action corrective", color: "var(--tc-green)", recommended: true },
    { id: "REMEDIATE_WITH_APPROVAL", icon: ShieldCheck, label: "Remédiation supervisée", desc: "Avec approbation humaine (HITL)", color: "var(--tc-amber)" },
    { id: "FULL_AUTO", icon: Zap, label: "Automatisation complète", desc: "Environnement maîtrisé uniquement", color: "var(--tc-red)", warning: true },
  ];

  const channelDefs = [
    { key: "slack", label: "Slack", desc: "Chat bidirectionnel + HITL", fields: [
      { id: "botToken", label: "Bot Token (xoxb-...)", placeholder: "xoxb-..." },
      { id: "signingSecret", label: "Signing Secret", placeholder: "Slack App > Basic Information" },
    ]},
    { key: "telegram", label: "Telegram", desc: "Chat bidirectionnel + alertes", fields: [
      { id: "botToken", label: "Bot Token", placeholder: "123456:ABC-DEF..." },
      { id: "botUsername", label: "Nom du bot (sans @)", placeholder: "threatclaw_bot" },
    ]},
    { key: "discord", label: "Discord", desc: "Slash commands + mentions", fields: [
      { id: "botToken", label: "Bot Token", placeholder: "Discord Developer Portal > Bot" },
      { id: "publicKey", label: "Public Key (hex)", placeholder: "General Information > Public Key" },
    ]},
    { key: "whatsapp", label: "WhatsApp", desc: "WhatsApp Cloud API (Meta)", fields: [
      { id: "accessToken", label: "Access Token", placeholder: "Token permanent Meta Developer" },
      { id: "phoneNumberId", label: "Phone Number ID", placeholder: "ID du numéro WhatsApp Business" },
    ]},
    { key: "email", label: "Email", desc: "Alertes uniquement (unidirectionnel)", fields: [
      { id: "host", label: "Serveur SMTP", placeholder: "smtp.example.com" },
      { id: "port", label: "Port", placeholder: "587" },
      { id: "from", label: "Expéditeur", placeholder: "threatclaw@example.com" },
      { id: "to", label: "Destinataire RSSI", placeholder: "rssi@example.com" },
    ]},
  ];

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "16px", background: "var(--tc-bg)" }}>
      {/* Skip button — top right */}
      <button onClick={skipOnboarding}
        style={{ position: "fixed", top: "16px", right: "16px", ...btnSecondary, fontSize: "10px", gap: "4px", opacity: 0.7 }}>
        <X size={10} /> Configurer plus tard
      </button>

      {/* Progress */}
      <div style={{ display: "flex", alignItems: "center", gap: "4px", marginBottom: "20px", maxWidth: "560px", width: "100%" }}>
        {STEPS.map((s, i) => (
          <React.Fragment key={s.id}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "2px" }}>
              <div style={{
                width: "24px", height: "24px", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: "9px", fontWeight: 800,
                background: i < step ? "var(--tc-green)" : i === step ? "var(--tc-surface-alt)" : "var(--tc-input)",
                border: i === step ? "2px solid var(--tc-red)" : "1px solid var(--tc-border)",
                color: i < step ? "#fff" : i === step ? "var(--tc-red)" : "var(--tc-text-muted)",
              }}>
                {i < step ? <Check size={10} /> : i + 1}
              </div>
              <span style={{ fontSize: "7px", fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase", color: i === step ? "var(--tc-red)" : "var(--tc-text-muted)" }}>{s.label}</span>
            </div>
            {i < STEPS.length - 1 && <div style={{ flex: 1, height: "2px", borderRadius: "1px", background: i < step ? "var(--tc-green)" : "var(--tc-border)" }} />}
          </React.Fragment>
        ))}
      </div>

      <div style={{ ...cardStyle, maxWidth: "540px", width: "100%" }}>

        {/* ── Step 0: Welcome ── */}
        {step === 0 && (
          <div style={{ textAlign: "center" }}>
            <div style={{ width: "56px", height: "56px", borderRadius: "14px", margin: "0 auto 12px", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--tc-input)", border: "1px solid var(--tc-border)" }}>
              <Shield size={28} color="var(--tc-red)" />
            </div>
            <h1 style={{ fontSize: "18px", fontWeight: 800, color: "var(--tc-text)", margin: "0 0 6px" }}>Bienvenue dans ThreatClaw</h1>
            <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", margin: "0 0 4px" }}>Agent de cybersécurité autonome pour PME</p>
            <p style={{ fontSize: "9px", color: "var(--tc-text-muted)", margin: "0 0 16px", maxWidth: "380px", marginLeft: "auto", marginRight: "auto" }}>
              Configurez votre agent en quelques étapes. Connectez votre IA, vos canaux de communication, et définissez votre niveau de sécurité.
            </p>
            <button onClick={next} style={btnPrimary}>
              Commencer <ChevronRight size={14} />
            </button>
          </div>
        )}

        {/* ── Step 1: Fiche entreprise ── */}
        {step === 1 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
              <Shield size={18} color="var(--tc-red)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--tc-text)" }}>Votre entreprise</span>
            </div>
            <p style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>
              Ces informations aident ThreatClaw à adapter ses détections à votre contexte.
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <div>
                <label style={labelStyle}>Nom de l{"'"}entreprise</label>
                <input value={company.company_name} onChange={e => setCompany(c => ({ ...c, company_name: e.target.value }))}
                  placeholder="CyberConsulting.fr" style={inputStyle} />
              </div>

              <div>
                <label style={labelStyle}>Secteur d{"'"}activité</label>
                <select value={company.sector} onChange={e => setCompany(c => ({ ...c, sector: e.target.value }))} style={inputStyle}>
                  <option value="industry">Industrie / Manufacturing</option>
                  <option value="healthcare">Santé / Médical</option>
                  <option value="finance">Finance / Assurance</option>
                  <option value="retail">Commerce / Retail</option>
                  <option value="government">Collectivité / Administration</option>
                  <option value="services">Services / Conseil</option>
                  <option value="transport">Transport / Logistique</option>
                  <option value="energy">Énergie</option>
                  <option value="education">Éducation</option>
                  <option value="other">Autre</option>
                </select>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                <div>
                  <label style={labelStyle}>Taille</label>
                  <select value={company.company_size} onChange={e => setCompany(c => ({ ...c, company_size: e.target.value }))} style={inputStyle}>
                    <option value="micro">&lt; 10 personnes</option>
                    <option value="small">10 - 50 personnes</option>
                    <option value="medium">50 - 250 personnes</option>
                    <option value="large">250+ personnes</option>
                  </select>
                </div>
                <div>
                  <label style={labelStyle}>Horaires d{"'"}activité</label>
                  <select value={company.business_hours} onChange={e => setCompany(c => ({ ...c, business_hours: e.target.value }))} style={inputStyle}>
                    <option value="office">Bureau (personnalisé)</option>
                    <option value="24x7">24h/7j</option>
                    <option value="shifts">Par équipes</option>
                  </select>
                  {company.business_hours !== "24x7" && (
                    <div style={{ display: "flex", gap: "8px", marginTop: "8px", alignItems: "center" }}>
                      <input type="time" value={company.business_hours_start || "08:00"}
                        onChange={e => setCompany(c => ({ ...c, business_hours_start: e.target.value }))}
                        style={{ ...inputStyle, flex: 1, padding: "8px 10px" }} />
                      <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>à</span>
                      <input type="time" value={company.business_hours_end || "18:00"}
                        onChange={e => setCompany(c => ({ ...c, business_hours_end: e.target.value }))}
                        style={{ ...inputStyle, flex: 1, padding: "8px 10px" }} />
                    </div>
                  )}
                </div>
              </div>

              <div>
                <label style={labelStyle}>Zone géographique</label>
                <select value={company.geo_scope} onChange={e => setCompany(c => ({ ...c, geo_scope: e.target.value }))} style={inputStyle}>
                  <option value="france">France uniquement</option>
                  <option value="europe">Europe</option>
                  <option value="international">International</option>
                </select>
              </div>

              <div>
                <label style={labelStyle}>Réseaux internes (CIDR, un par ligne)</label>
                <textarea value={company.internal_networks}
                  onChange={e => setCompany(c => ({ ...c, internal_networks: e.target.value }))}
                  placeholder={"192.168.1.0/24\n10.0.0.0/8"}
                  style={{ ...inputStyle, minHeight: "50px", resize: "vertical" }} />
              </div>

              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontStyle: "italic" }}>
                Ces données restent 100% locales. Elles paramètrent les seuils de détection et ne quittent jamais votre serveur.
              </div>
            </div>
          </div>
        )}

        {/* ── Step 2: IA Principale ── */}
        {step === 2 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
              <Cpu size={18} color="var(--tc-red)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--tc-text)" }}>IA Principale</span>
            </div>
            <p style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>
              Le cerveau de ThreatClaw. Choisissez comment connecter l{"'"}IA.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", marginBottom: "12px" }}>
              {[
                { id: "ollama", label: "Ollama Local", desc: "100% on-premise", icon: Server, cloud: false },
                { id: "ollama_remote", label: "Ollama Distant", desc: "Serveur existant", icon: Link2, cloud: false },
                { id: "mistral", label: "Mistral AI", desc: "Souveraineté FR", icon: Shield, cloud: true },
                { id: "anthropic", label: "Anthropic", desc: "Claude", icon: Cpu, cloud: true },
              ].map(b => (
                <button key={b.id} onClick={() => { setPrimary(p => ({ ...p, backend: b.id, connected: false, models: [] })); setAnonymizePrimary(b.cloud); }}
                  style={{
                    ...cardSmStyle, cursor: "pointer", textAlign: "left" as const,
                    border: primary.backend === b.id ? "1px solid var(--tc-red)" : "1px solid var(--tc-border)",
                  }}>
                  <b.icon size={14} color={primary.backend === b.id ? "var(--tc-red)" : "var(--tc-text-muted)"} />
                  <div style={{ fontSize: "10px", fontWeight: 700, color: primary.backend === b.id ? "var(--tc-red)" : "var(--tc-text)", marginTop: "2px" }}>{b.label}</div>
                  <div style={{ fontSize: "8px", color: "var(--tc-text-muted)" }}>{b.desc}</div>
                </button>
              ))}
            </div>

            {/* URL */}
            {(primary.backend === "ollama" || primary.backend === "ollama_remote") && (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <div style={{ display: "flex", gap: "6px" }}>
                  <input value={primary.url} onChange={e => setPrimary(p => ({ ...p, url: e.target.value }))}
                    style={{ ...inputStyle, flex: 1 }} placeholder="http://localhost:11434" />
                  <button onClick={testOllamaConnection} disabled={primary.testing} style={btnSecondary}>
                    {primary.testing ? <Loader2 size={10} className="animate-spin" /> : <Wifi size={10} />}
                    {primary.testing ? "Test..." : "Tester"}
                  </button>
                </div>
                {primary.connected && (
                  <div style={{ fontSize: "9px", color: "var(--tc-green)", display: "flex", alignItems: "center", gap: "4px" }}>
                    <CheckCircle2 size={10} /> Connecté — {primary.models.length} modèle(s)
                  </div>
                )}
                {primary.models.length > 0 && (
                  <select value={primary.model} onChange={e => setPrimary(p => ({ ...p, model: e.target.value }))} style={inputStyle}>
                    {primary.models.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                )}
              </div>
            )}

            {(primary.backend === "mistral" || primary.backend === "anthropic") && (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <input value={primary.apiKey} onChange={e => setPrimary(p => ({ ...p, apiKey: e.target.value }))}
                  style={inputStyle} type="password" placeholder={primary.backend === "mistral" ? "Clé API Mistral" : "Clé API Anthropic"} />
                <input value={primary.model} onChange={e => setPrimary(p => ({ ...p, model: e.target.value }))}
                  style={inputStyle} placeholder={primary.backend === "mistral" ? "mistral-large-latest" : "claude-sonnet-4-20250514"} />

                {/* Anonymization toggle */}
                <button onClick={() => setAnonymizePrimary(!anonymizePrimary)}
                  style={{ display: "flex", width: "100%", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                  <div style={{ flex: 1, textAlign: "left" }}>
                    <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text)" }}>Anonymiser avant envoi</div>
                    <div style={{ fontSize: "8px", color: "var(--tc-text-muted)" }}>IPs, hostnames, emails et usernames anonymisés</div>
                  </div>
                  <input type="checkbox" className="tc-toggle" checked={anonymizePrimary} readOnly />
                </button>
              </div>
            )}
          </div>
        )}

        {/* ── Step 2: Cloud backup ── */}
        {step === 3 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <Cloud size={18} color="var(--tc-red)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--tc-text)" }}>IA de secours (Cloud)</span>
            </div>

            <button onClick={() => setCloud(c => ({ ...c, enabled: !c.enabled }))}
              style={{ display: "flex", width: "100%", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: 0, marginBottom: "12px" }}>
              <div style={{ flex: 1, textAlign: "left" }}>
                <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>Activer le cloud de secours</div>
                <div style={{ fontSize: "8px", color: "var(--tc-text-muted)" }}>L{"'"}IA locale reste prioritaire — le cloud n{"'"}intervient que si la confiance est faible</div>
              </div>
              <input type="checkbox" className="tc-toggle" checked={cloud.enabled} readOnly />
            </button>

            {cloud.enabled && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "6px" }}>
                  {[
                    { id: "anthropic", label: "Anthropic" },
                    { id: "mistral", label: "Mistral AI" },
                    { id: "openai", label: "OpenAI" },
                  ].map(b => (
                    <button key={b.id} onClick={() => setCloud(c => ({ ...c, backend: b.id }))}
                      style={{ ...cardSmStyle, cursor: "pointer", textAlign: "center" as const,
                        border: cloud.backend === b.id ? "1px solid var(--tc-red)" : "1px solid var(--tc-border)",
                        fontSize: "10px", fontWeight: 600, color: cloud.backend === b.id ? "var(--tc-red)" : "var(--tc-text)" }}>
                      {b.label}
                    </button>
                  ))}
                </div>
                <input value={cloud.apiKey} onChange={e => setCloud(c => ({ ...c, apiKey: e.target.value }))}
                  style={inputStyle} type="password" placeholder="Clé API" />
                <input value={cloud.model} onChange={e => setCloud(c => ({ ...c, model: e.target.value }))}
                  style={inputStyle} placeholder="Modèle (ex: claude-sonnet-4-20250514)" />
              </div>
            )}
          </div>
        )}

        {/* ── Step 3: Communication ── */}
        {step === 4 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <MessageSquare size={18} color="var(--tc-red)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--tc-text)" }}>Communication</span>
            </div>
            <p style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>Optionnel — vous pourrez configurer plus tard dans Config.</p>

            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {channelDefs.map(ch => {
                const isEnabled = channels[ch.key]?.enabled;
                return (
                  <div key={ch.key} style={cardSmStyle}>
                    <button onClick={() => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], enabled: !isEnabled } }))}
                      style={{ display: "flex", width: "100%", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                      <div style={{ flex: 1, textAlign: "left" }}>
                        <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>{ch.label}</div>
                        <div style={{ fontSize: "8px", color: "var(--tc-text-muted)" }}>{ch.desc}</div>
                      </div>
                      <input type="checkbox" className="tc-toggle" checked={isEnabled} readOnly />
                    </button>

                    {isEnabled && (
                      <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "8px", borderTop: "1px solid var(--tc-border)", paddingTop: "8px" }}>
                        {ch.fields.map(f => (
                          <input key={f.id} value={(channels[ch.key][f.id] || "") as string}
                            onChange={e => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], [f.id]: e.target.value } }))}
                            style={inputStyle} placeholder={f.placeholder} type={f.id.toLowerCase().includes("token") || f.id.toLowerCase().includes("secret") ? "password" : "text"} />
                        ))}
                        <button onClick={() => testChannel(ch.key)} disabled={channelTest[ch.key]?.testing} style={{ ...btnSecondary, alignSelf: "flex-start", marginTop: "4px" }}>
                          {channelTest[ch.key]?.testing
                            ? <><Loader2 size={10} className="animate-spin" /> Test...</>
                            : channelTest[ch.key]?.result?.ok
                              ? <><CheckCircle2 size={10} color="var(--tc-green)" /> Connecté</>
                              : <><Wifi size={10} /> Tester</>}
                        </button>
                        {channelTest[ch.key]?.result && !channelTest[ch.key]?.result?.ok && (
                          <span style={{ fontSize: "8px", color: "var(--tc-red)" }}>{channelTest[ch.key]?.result?.error}</span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Step 4: Security ── */}
        {step === 5 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <ShieldAlert size={18} color="var(--tc-red)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--tc-text)" }}>Niveau de sécurité</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {permLevels.map(level => {
                const Icon = level.icon; const sel = permLevel === level.id;
                return (
                  <button key={level.id} onClick={() => setPermLevel(level.id)}
                    style={{
                      ...cardSmStyle, cursor: "pointer", display: "flex", alignItems: "center", gap: "8px", textAlign: "left" as const,
                      border: sel ? `1px solid ${level.color}` : "1px solid var(--tc-border)",
                    }}>
                    <Icon size={16} color={level.color} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <span style={{ fontSize: "10px", fontWeight: 800, color: "var(--tc-text)" }}>{level.label}</span>
                        {level.recommended && <span style={{ fontSize: "7px", fontWeight: 700, color: "var(--tc-green)", background: "rgba(48,160,80,0.08)", padding: "1px 4px", borderRadius: "6px", textTransform: "uppercase" }}>Recommandé</span>}
                        {level.warning && <span style={{ fontSize: "7px", color: "var(--tc-red)", display: "flex", alignItems: "center", gap: "2px" }}><AlertTriangle size={8} />Avancé</span>}
                      </div>
                      <p style={{ fontSize: "8px", color: "var(--tc-text-muted)", margin: "2px 0 0" }}>{level.desc}</p>
                    </div>
                    <div style={{
                      width: "14px", height: "14px", borderRadius: "50%",
                      background: sel ? level.color : "var(--tc-input)", border: sel ? "none" : "1px solid var(--tc-border)",
                      display: "flex", alignItems: "center", justifyContent: "center",
                    }}>
                      {sel && <Check size={8} color="#fff" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Step 5: Confirm ── */}
        {step === 6 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <CheckCircle2 size={18} color="var(--tc-red)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--tc-text)" }}>Récapitulatif</span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "16px" }}>
              {[
                { label: "IA Principale", value: `${primary.backend === "ollama" ? "Ollama local" : primary.backend === "ollama_remote" ? "Ollama distant" : primary.backend} — ${primary.model || "non configuré"}` },
                { label: "IA Cloud", value: cloud.enabled ? `${cloud.backend} (${cloud.escalation})` : "Désactivé — 100% local" },
                { label: "Communication", value: Object.entries(channels).filter(([, v]) => v.enabled).map(([k]) => k.charAt(0).toUpperCase() + k.slice(1)).join(", ") || "Aucun canal" },
                { label: "Sécurité", value: permLevels.find(l => l.id === permLevel)?.label || permLevel },
              ].map(item => (
                <div key={item.label} style={{ ...cardSmStyle, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "9px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{item.label}</span>
                  <span style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text)" }}>{item.value}</span>
                </div>
              ))}
            </div>

            {saved ? (
              <div style={{ textAlign: "center" }}>
                <CheckCircle2 size={28} color="var(--tc-green)" style={{ margin: "0 auto 8px", display: "block" }} />
                <div style={{ fontSize: "12px", fontWeight: 800, color: "var(--tc-green)", marginBottom: "12px" }}>Configuration sauvegardée !</div>
                <button onClick={() => window.location.href = "/skills"} style={{ ...btnPrimary, width: "100%", justifyContent: "center" }}>
                  <Puzzle size={14} /> Explorer les Skills
                </button>
                <button onClick={() => window.location.href = "/"} style={{ display: "block", fontSize: "9px", color: "var(--tc-text-muted)", background: "none", border: "none", cursor: "pointer", textAlign: "center", marginTop: "8px", width: "100%", fontFamily: "inherit" }}>
                  Aller au Dashboard
                </button>
              </div>
            ) : (
              <button onClick={handleSave} disabled={saving} style={{ ...btnPrimary, width: "100%", justifyContent: "center" }}>
                {saving ? <><Loader2 size={14} className="animate-spin" /> Sauvegarde...</> : <><Zap size={14} /> Sauvegarder et lancer</>}
              </button>
            )}
          </div>
        )}

        {/* Navigation */}
        {step > 0 && step < 6 && (
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: "16px" }}>
            <button onClick={prev} style={btnSecondary}><ChevronLeft size={12} /> Précédent</button>
            <button onClick={next} style={{ ...btnSecondary, color: "var(--tc-red)" }}>Suivant <ChevronRight size={12} /></button>
          </div>
        )}
        {step === 6 && !saved && (
          <button onClick={prev} style={{ ...btnSecondary, marginTop: "8px" }}><ChevronLeft size={12} /> Modifier</button>
        )}
      </div>
    </div>
  );
}

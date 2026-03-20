"use client";

import React, { useState, useEffect } from "react";
import {
  Shield, ChevronRight, ChevronLeft, Cpu, Link2, ShieldCheck, Calendar,
  CheckCircle2, Eye, Bell, ShieldAlert, Zap, MessageSquare, Mail, Server,
  Check, Loader2, Wifi, AlertTriangle, Puzzle, Cloud, Lock,
} from "lucide-react";

const STEPS = [
  { id: "welcome", label: "Bienvenue" },
  { id: "llm-primary", label: "IA Principale" },
  { id: "llm-cloud", label: "IA Cloud" },
  { id: "communication", label: "Communication" },
  { id: "security", label: "Sécurité" },
  { id: "schedule", label: "Planning" },
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

export default function SetupWizard() {
  const [step, setStep] = useState(0);

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

  const [schedules, setSchedules] = useState<Record<string, ScheduleItem>>({
    vuln_scan: { enabled: true, label: "Scan vulnérabilités", description: "Scan réseau quotidien", default: "Tous les jours à 2h", cron: "0 2 * * *" },
    log_analysis: { enabled: true, label: "Analyse logs SOC", description: "Analyse continue des logs", default: "Toutes les 5 minutes", cron: "*/5 * * * *" },
    darkweb: { enabled: true, label: "Surveillance dark web", description: "Monitoring fuites de données", default: "Toutes les 6 heures", cron: "0 */6 * * *" },
    cloud_posture: { enabled: true, label: "Audit cloud", description: "Posture cloud AWS/Azure/GCP", default: "Chaque lundi à 3h", cron: "0 3 * * 1" },
    phishing: { enabled: false, label: "Campagne phishing", description: "Simulation mensuelle", default: "1er du mois à 10h", cron: "0 10 1 * *" },
    report: { enabled: true, label: "Rapport hebdomadaire", description: "Rapport sécurité RSSI", default: "Vendredi à 8h", cron: "0 8 * * 5" },
  });

  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  // Auto-detect RAM on mount
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

  const handleSave = () => {
    setSaving(true);
    const config = {
      llm: { backend: primary.backend, url: primary.url, model: primary.model, apiKey: primary.apiKey },
      cloud: cloud.enabled ? { backend: cloud.backend, model: cloud.model, baseUrl: cloud.baseUrl, apiKey: cloud.apiKey, escalation: cloud.escalation } : null,
      channels, permLevel, schedules,
    };
    localStorage.setItem("threatclaw_config", JSON.stringify(config));
    localStorage.setItem("threatclaw_onboarded", "true");
    setTimeout(() => { setSaving(false); setSaved(true); }, 1500);
  };

  const next = () => setStep(s => Math.min(s + 1, STEPS.length - 1));
  const prev = () => setStep(s => Math.max(s - 1, 0));

  const permLevels = [
    { id: "READ_ONLY", icon: Eye, label: "Observation", desc: "Observation uniquement — aucune action", color: "var(--accent-info)" },
    { id: "ALERT_ONLY", icon: Bell, label: "Alertes", desc: "Alertes sans action corrective", color: "var(--accent-ok)", recommended: true },
    { id: "REMEDIATE_WITH_APPROVAL", icon: ShieldCheck, label: "Remédiation supervisée", desc: "Avec approbation humaine (HITL)", color: "var(--accent-warning)" },
    { id: "FULL_AUTO", icon: Zap, label: "Automatisation complète", desc: "Environnement maîtrisé uniquement", color: "var(--accent-danger)", warning: true },
  ];

  const channelDefs = [
    { key: "slack", label: "Slack", desc: "Chat bidirectionnel + HITL — Slack App requise", fields: [
      { id: "botToken", label: "Bot Token (xoxb-...)", placeholder: "xoxb-..." },
      { id: "signingSecret", label: "Signing Secret", placeholder: "Slack App > Basic Information" },
    ]},
    { key: "telegram", label: "Telegram", desc: "Chat bidirectionnel + alertes — Bot via @BotFather", fields: [
      { id: "botToken", label: "Bot Token", placeholder: "123456:ABC-DEF..." },
      { id: "botUsername", label: "Nom du bot (sans @)", placeholder: "threatclaw_bot" },
    ]},
    { key: "discord", label: "Discord", desc: "Chat via bot Discord — slash commands + mentions", fields: [
      { id: "botToken", label: "Bot Token", placeholder: "Discord Developer Portal > Bot" },
      { id: "publicKey", label: "Public Key (hex)", placeholder: "General Information > Public Key" },
    ]},
    { key: "whatsapp", label: "WhatsApp", desc: "Chat via WhatsApp Cloud API (Meta Business)", fields: [
      { id: "accessToken", label: "Access Token", placeholder: "Token permanent Meta Developer" },
      { id: "phoneNumberId", label: "Phone Number ID", placeholder: "ID du numéro WhatsApp Business" },
    ]},
    { key: "signal", label: "Signal", desc: "Chat chiffré — nécessite signal-cli (avancé)", fields: [
      { id: "httpUrl", label: "URL signal-cli", placeholder: "http://localhost:8080" },
      { id: "account", label: "Numéro Signal (+33...)", placeholder: "+33612345678" },
    ]},
    { key: "email", label: "Email", desc: "Alertes uniquement (unidirectionnel)", fields: [
      { id: "host", label: "Serveur SMTP", placeholder: "smtp.example.com" },
      { id: "port", label: "Port", placeholder: "587" },
      { id: "from", label: "Expéditeur", placeholder: "threatclaw@example.com" },
      { id: "to", label: "Destinataire RSSI", placeholder: "rssi@example.com" },
    ]},
  ];

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "16px", background: "var(--bg-base)" }}>
      {/* Progress */}
      <div style={{ display: "flex", alignItems: "center", gap: "4px", marginBottom: "20px", maxWidth: "560px", width: "100%" }}>
        {STEPS.map((s, i) => (
          <React.Fragment key={s.id}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "2px" }}>
              <div style={{
                width: "24px", height: "24px", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: "9px", fontWeight: 800,
                background: i < step ? "var(--accent-ok)" : "var(--bg-pit)",
                boxShadow: i === step ? "var(--shadow-pit-xs), 0 0 0 2px var(--accent-danger)" : "var(--shadow-pit-xs)",
                color: i < step ? "#fff" : i === step ? "var(--accent-danger)" : "var(--text-muted)",
              }}>
                {i < step ? <Check size={10} /> : i + 1}
              </div>
              <span style={{ fontSize: "7px", fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase", color: i === step ? "var(--accent-danger)" : "var(--text-muted)" }}>{s.label}</span>
            </div>
            {i < STEPS.length - 1 && <div style={{ flex: 1, height: "2px", borderRadius: "1px", background: i < step ? "var(--accent-ok)" : "var(--bg-pit)", boxShadow: "var(--shadow-track)" }} />}
          </React.Fragment>
        ))}
      </div>

      <div className="pit" style={{ maxWidth: "540px", width: "100%", padding: "24px" }}>

        {/* ── Step 0: Welcome ── */}
        {step === 0 && (
          <div style={{ textAlign: "center" }}>
            <div className="pit" style={{ width: "56px", height: "56px", borderRadius: "14px", margin: "0 auto 12px", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Shield size={28} color="var(--accent-danger)" />
            </div>
            <h1 style={{ fontSize: "18px", fontWeight: 800, color: "var(--text-primary)", margin: "0 0 6px" }}>Bienvenue dans ThreatClaw</h1>
            <p style={{ fontSize: "11px", color: "var(--text-secondary)", margin: "0 0 4px" }}>Agent de cybersécurité autonome pour PME</p>
            <p style={{ fontSize: "9px", color: "var(--text-muted)", margin: "0 0 16px", maxWidth: "380px", marginLeft: "auto", marginRight: "auto" }}>
              Configurez votre agent en quelques étapes. Connectez votre IA, vos canaux de communication, et définissez votre niveau de sécurité.
            </p>
            <button className="btn-raised-lg" onClick={next} style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
              Commencer <ChevronRight size={14} />
            </button>
          </div>
        )}

        {/* ── Step 1: IA Principale (obligatoire) ── */}
        {step === 1 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
              <Cpu size={18} color="var(--accent-danger)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--text-primary)" }}>IA Principale</span>
            </div>
            <p style={{ fontSize: "9px", color: "var(--text-muted)", marginBottom: "12px" }}>
              Le cerveau de ThreatClaw. Choisissez comment connecter l{"'"}IA.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", marginBottom: "12px" }}>
              {[
                { id: "ollama", label: "Ollama Local", desc: "100% on-premise", icon: Server },
                { id: "ollama_remote", label: "Ollama Distant", desc: "Serveur existant", icon: Link2 },
                { id: "mistral", label: "Mistral AI", desc: "Souveraineté FR", icon: Shield },
                { id: "anthropic", label: "Anthropic", desc: "Claude", icon: Cpu },
              ].map(b => (
                <button key={b.id} onClick={() => setPrimary(p => ({ ...p, backend: b.id, connected: false, models: [] }))}
                  className={primary.backend === b.id ? "pit" : "pit-xs"}
                  style={{ border: "none", cursor: "pointer", textAlign: "left", outline: primary.backend === b.id ? "1px solid var(--border-accent)" : "none", outlineOffset: "-1px" }}>
                  <b.icon size={14} color={primary.backend === b.id ? "var(--accent-danger)" : "var(--text-muted)"} />
                  <div style={{ fontSize: "10px", fontWeight: 700, color: primary.backend === b.id ? "var(--accent-danger)" : "var(--text-primary)", marginTop: "2px" }}>{b.label}</div>
                  <div style={{ fontSize: "8px", color: "var(--text-muted)" }}>{b.desc}</div>
                </button>
              ))}
            </div>

            {(primary.backend === "ollama" || primary.backend === "ollama_remote") && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <div>
                  <div className="label-caps" style={{ marginBottom: "3px" }}>
                    {primary.backend === "ollama" ? "URL Ollama (local)" : "URL du serveur Ollama"}
                  </div>
                  <div style={{ display: "flex", gap: "6px" }}>
                    <input type="text" value={primary.url} onChange={e => setPrimary(p => ({ ...p, url: e.target.value }))} className="input-pit" style={{ flex: 1 }}
                      placeholder={primary.backend === "ollama" ? "http://localhost:11434" : "http://192.168.1.50:11434"} />
                    <button onClick={testOllamaConnection} disabled={primary.testing} className="btn-raised" style={{ padding: "8px 10px", display: "flex", alignItems: "center", gap: "3px" }}>
                      {primary.testing ? <Loader2 size={12} className="animate-spin" /> : primary.connected ? <CheckCircle2 size={12} color="var(--accent-ok)" /> : <Wifi size={12} />}
                      Tester
                    </button>
                  </div>
                </div>
                {primary.connected && primary.models.length > 0 && (
                  <div>
                    <div className="label-caps" style={{ marginBottom: "3px" }}>Modèle</div>
                    <select value={primary.model} onChange={e => setPrimary(p => ({ ...p, model: e.target.value }))} className="input-pit">
                      {primary.models.map(m => <option key={m} value={m}>{m}</option>)}
                    </select>
                    <div style={{ display: "flex", alignItems: "center", gap: "4px", marginTop: "4px", fontSize: "9px", color: "var(--accent-ok)" }}>
                      <CheckCircle2 size={10} /> Connecté — {primary.models.length} modèle(s)
                    </div>
                    {primary.recommendedModel && (
                      <div style={{ fontSize: "8px", color: "var(--accent-info)", marginTop: "2px" }}>
                        Recommandé pour votre RAM : {primary.recommendedModel}
                      </div>
                    )}
                  </div>
                )}
                {primary.backend === "ollama" && !primary.connected && (
                  <div className="pit-xs" style={{ fontSize: "9px", color: "var(--text-muted)" }}>
                    Si Ollama n{"'"}est pas installé, ThreatClaw le téléchargera automatiquement avec le modèle recommandé pour votre machine.
                  </div>
                )}
              </div>
            )}

            {(primary.backend === "mistral" || primary.backend === "anthropic") && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <div>
                  <div className="label-caps" style={{ marginBottom: "3px" }}>Clé API</div>
                  <input type="password" value={primary.apiKey} onChange={e => setPrimary(p => ({ ...p, apiKey: e.target.value }))} className="input-pit"
                    placeholder={primary.backend === "mistral" ? "sk-..." : "sk-ant-..."} />
                </div>
                <div>
                  <div className="label-caps" style={{ marginBottom: "3px" }}>Modèle</div>
                  <input type="text" value={primary.model} onChange={e => setPrimary(p => ({ ...p, model: e.target.value }))} className="input-pit"
                    placeholder={primary.backend === "mistral" ? "mistral-large-latest" : "claude-sonnet-4-20250514"} />
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Step 2: IA Cloud de secours (optionnel) ── */}
        {step === 2 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
              <Cloud size={18} color="var(--accent-info)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--text-primary)" }}>IA Cloud de secours</span>
            </div>
            <p style={{ fontSize: "9px", color: "var(--text-muted)", marginBottom: "12px" }}>
              Optionnel — pour les analyses complexes, ThreatClaw peut escalader vers un LLM cloud.
              Vos données sont <strong>anonymisées</strong> avant envoi.
            </p>

            {/* Enable toggle */}
            <div className="pit-sm" style={{ marginBottom: "12px" }}>
              <button onClick={() => setCloud(c => ({ ...c, enabled: !c.enabled }))}
                style={{ display: "flex", width: "100%", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                <div style={{ flex: 1, textAlign: "left" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-primary)" }}>Activer le cloud de secours</div>
                  <div style={{ fontSize: "8px", color: "var(--text-muted)" }}>L{"'"}IA locale reste prioritaire — le cloud n{"'"}intervient que si la confiance est faible</div>
                </div>
                <div className={`toggle-track${cloud.enabled ? " active" : ""}`}><div className="toggle-thumb" /></div>
              </button>
            </div>

            {cloud.enabled && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {/* Cloud provider */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "6px" }}>
                  {[
                    { id: "anthropic", label: "Anthropic", model: "claude-sonnet-4-20250514" },
                    { id: "mistral", label: "Mistral AI", model: "mistral-large-latest" },
                    { id: "openai_compatible", label: "Compatible", model: "" },
                  ].map(b => (
                    <button key={b.id} onClick={() => setCloud(c => ({ ...c, backend: b.id, model: b.model }))}
                      className={cloud.backend === b.id ? "pit" : "pit-xs"}
                      style={{ border: "none", cursor: "pointer", textAlign: "center", outline: cloud.backend === b.id ? "1px solid var(--accent-info)" : "none", outlineOffset: "-1px" }}>
                      <div style={{ fontSize: "10px", fontWeight: 700, color: cloud.backend === b.id ? "var(--accent-info)" : "var(--text-primary)" }}>{b.label}</div>
                    </button>
                  ))}
                </div>

                <div>
                  <div className="label-caps" style={{ marginBottom: "3px" }}>Clé API</div>
                  <input type="password" value={cloud.apiKey} onChange={e => setCloud(c => ({ ...c, apiKey: e.target.value }))} className="input-pit" placeholder="sk-..." />
                </div>

                <div>
                  <div className="label-caps" style={{ marginBottom: "3px" }}>Modèle</div>
                  <input type="text" value={cloud.model} onChange={e => setCloud(c => ({ ...c, model: e.target.value }))} className="input-pit" />
                </div>

                {cloud.backend === "openai_compatible" && (
                  <div>
                    <div className="label-caps" style={{ marginBottom: "3px" }}>URL de base</div>
                    <input type="text" value={cloud.baseUrl} onChange={e => setCloud(c => ({ ...c, baseUrl: e.target.value }))} className="input-pit" placeholder="https://api.example.com/v1" />
                  </div>
                )}

                {/* Escalation policy */}
                <div>
                  <div className="label-caps" style={{ marginBottom: "3px" }}>Politique d{"'"}envoi</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    {[
                      { id: "anonymized" as const, label: "Anonymisé", desc: "Données anonymisées avant envoi (recommandé)", icon: Lock, color: "var(--accent-ok)" },
                      { id: "direct" as const, label: "Direct", desc: "Données envoyées sans anonymisation", icon: AlertTriangle, color: "var(--accent-warning)" },
                      { id: "never" as const, label: "Jamais", desc: "Ne jamais utiliser le cloud", icon: ShieldAlert, color: "var(--text-muted)" },
                    ].map(p => (
                      <button key={p.id} onClick={() => setCloud(c => ({ ...c, escalation: p.id }))}
                        className="pit-xs"
                        style={{ border: "none", cursor: "pointer", display: "flex", alignItems: "center", gap: "6px", textAlign: "left",
                          outline: cloud.escalation === p.id ? `1px solid ${p.color}` : "none", outlineOffset: "-1px" }}>
                        <p.icon size={12} color={p.color} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--text-primary)" }}>{p.label}</div>
                          <div style={{ fontSize: "8px", color: "var(--text-muted)" }}>{p.desc}</div>
                        </div>
                        {cloud.escalation === p.id && <CheckCircle2 size={10} color={p.color} />}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {!cloud.enabled && (
              <div className="pit-xs" style={{ textAlign: "center", fontSize: "9px", color: "var(--text-muted)" }}>
                100% local — aucune donnée ne quittera votre infrastructure
              </div>
            )}
          </div>
        )}

        {/* ── Step 3: Communication ── */}
        {step === 3 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
              <MessageSquare size={18} color="var(--accent-danger)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--text-primary)" }}>Communication</span>
            </div>
            <p style={{ fontSize: "9px", color: "var(--text-muted)", marginBottom: "10px" }}>Optionnel — configurable plus tard.</p>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {channelDefs.map(ch => (
                <div key={ch.key} className="pit-sm">
                  <button onClick={() => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], enabled: !p[ch.key].enabled } }))}
                    style={{ display: "flex", width: "100%", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                    <div style={{ flex: 1, textAlign: "left" }}>
                      <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-primary)" }}>{ch.label}</div>
                      <div style={{ fontSize: "8px", color: "var(--text-muted)" }}>{ch.desc}</div>
                    </div>
                    <div className={`toggle-track${channels[ch.key].enabled ? " active" : ""}`}><div className="toggle-thumb" /></div>
                  </button>
                  {channels[ch.key].enabled && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "6px", borderTop: "1px solid var(--border-subtle)", paddingTop: "6px" }}>
                      {ch.fields.map(f => (
                        <div key={f.id}>
                          <div className="label-caps" style={{ marginBottom: "2px", fontSize: "8px" }}>{f.label}</div>
                          <input type={f.id.toLowerCase().includes("token") || f.id.toLowerCase().includes("key") ? "password" : "text"}
                            value={(channels[ch.key][f.id] as string) || ""} onChange={e => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], [f.id]: e.target.value } }))}
                            className="input-pit" style={{ fontSize: "10px", padding: "6px 8px" }} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Step 4: Security ── */}
        {step === 4 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <ShieldAlert size={18} color="var(--accent-danger)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--text-primary)" }}>Niveau de sécurité</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {permLevels.map(level => {
                const Icon = level.icon; const sel = permLevel === level.id;
                return (
                  <button key={level.id} onClick={() => setPermLevel(level.id)} className={sel ? "pit" : "pit-sm"}
                    style={{ border: "none", cursor: "pointer", display: "flex", alignItems: "center", gap: "8px", textAlign: "left", outline: sel ? `1px solid ${level.color}` : "none", outlineOffset: "-1px" }}>
                    <Icon size={16} color={level.color} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <span style={{ fontSize: "10px", fontWeight: 800, color: "var(--text-primary)" }}>{level.label}</span>
                        {level.recommended && <span style={{ fontSize: "7px", fontWeight: 700, color: "var(--accent-ok)", background: "var(--pill-ok-bg)", padding: "1px 4px", borderRadius: "6px", textTransform: "uppercase" }}>Recommandé</span>}
                        {level.warning && <span style={{ fontSize: "7px", color: "var(--accent-danger)", display: "flex", alignItems: "center", gap: "2px" }}><AlertTriangle size={8} />Avancé</span>}
                      </div>
                      <p style={{ fontSize: "8px", color: "var(--text-muted)", margin: "2px 0 0" }}>{level.desc}</p>
                    </div>
                    <div style={{ width: "14px", height: "14px", borderRadius: "50%", background: sel ? level.color : "var(--bg-pit)", boxShadow: sel ? "none" : "var(--shadow-pit-xs)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {sel && <Check size={8} color="#fff" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Step 5: Schedule ── */}
        {step === 5 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <Calendar size={18} color="var(--accent-danger)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--text-primary)" }}>Planning des scans</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {Object.entries(schedules).map(([key, sched]) => (
                <div key={key} className="pit-sm" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--text-primary)" }}>{sched.label}</div>
                    <div style={{ fontSize: "8px", color: "var(--text-muted)", fontFamily: "monospace" }}>{sched.default}</div>
                  </div>
                  <button onClick={() => setSchedules(p => ({ ...p, [key]: { ...p[key], enabled: !p[key].enabled } }))}
                    style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}>
                    <div className={`toggle-track${sched.enabled ? " active" : ""}`}><div className="toggle-thumb" /></div>
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Step 6: Confirm ── */}
        {step === 6 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <CheckCircle2 size={18} color="var(--accent-danger)" />
              <span style={{ fontSize: "14px", fontWeight: 800, color: "var(--text-primary)" }}>Récapitulatif</span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "16px" }}>
              {[
                { label: "IA Principale", value: `${primary.backend === "ollama" ? "Ollama local" : primary.backend === "ollama_remote" ? "Ollama distant" : primary.backend} — ${primary.model || "non configuré"}` },
                { label: "IA Cloud", value: cloud.enabled ? `${cloud.backend} (${cloud.escalation})` : "Désactivé — 100% local" },
                { label: "Communication", value: Object.entries(channels).filter(([, v]) => v.enabled).map(([k]) => k.charAt(0).toUpperCase() + k.slice(1)).join(", ") || "Aucun canal" },
                { label: "Sécurité", value: permLevels.find(l => l.id === permLevel)?.label || permLevel },
                { label: "Scans", value: `${Object.values(schedules).filter(s => s.enabled).length} / ${Object.values(schedules).length} actifs` },
              ].map(item => (
                <div key={item.label} className="pit-xs" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span className="label-caps">{item.label}</span>
                  <span style={{ fontSize: "10px", fontWeight: 600, color: "var(--text-primary)" }}>{item.value}</span>
                </div>
              ))}
            </div>

            {saved ? (
              <div style={{ textAlign: "center" }}>
                <CheckCircle2 size={28} color="var(--accent-ok)" style={{ margin: "0 auto 8px" }} />
                <div style={{ fontSize: "12px", fontWeight: 800, color: "var(--accent-ok)", marginBottom: "12px" }}>Configuration sauvegardée !</div>
                <a href="/marketplace" className="btn-raised-lg" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "6px", textDecoration: "none", background: "var(--accent-danger)", color: "#fff" }}>
                  <Puzzle size={14} /> Explorer le Marketplace
                </a>
                <a href="/" style={{ display: "block", fontSize: "9px", color: "var(--text-muted)", textDecoration: "none", textAlign: "center", marginTop: "8px" }}>Aller au Dashboard</a>
              </div>
            ) : (
              <button onClick={handleSave} disabled={saving} className="btn-raised-lg" style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}>
                {saving ? <><Loader2 size={14} className="animate-spin" /> Sauvegarde...</> : <><Zap size={14} /> Sauvegarder</>}
              </button>
            )}
          </div>
        )}

        {/* Navigation */}
        {step > 0 && step < 6 && (
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: "16px" }}>
            <button onClick={prev} className="btn-raised" style={{ display: "flex", alignItems: "center", gap: "3px", padding: "6px 10px" }}><ChevronLeft size={12} /> Précédent</button>
            <button onClick={next} className="btn-raised" style={{ display: "flex", alignItems: "center", gap: "3px", padding: "6px 10px", color: "var(--accent-danger)" }}>Suivant <ChevronRight size={12} /></button>
          </div>
        )}
        {step === 6 && !saved && (
          <button onClick={prev} className="btn-raised" style={{ display: "flex", alignItems: "center", gap: "3px", padding: "6px 10px", marginTop: "8px" }}><ChevronLeft size={12} /> Modifier</button>
        )}
      </div>
    </div>
  );
}

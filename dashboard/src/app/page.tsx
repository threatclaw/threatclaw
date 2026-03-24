"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  CheckCircle2, XCircle, Loader2, Settings, Puzzle, Activity,
  Cpu, MessageSquare, Shield, Wifi, Server, ArrowRight, BarChart3,
} from "lucide-react";

interface ServiceStatus {
  name: string;
  icon: React.ReactNode;
  status: "ok" | "down" | "checking";
  detail?: string;
}

interface ConfigSummary {
  llm?: { backend: string; model: string; url: string };
  channels?: Record<string, { enabled: boolean }>;
  permissions?: string;
  anonymize_primary?: boolean;
}

export default function HomePage() {
  const [services, setServices] = useState<ServiceStatus[]>([
    { name: "Ollama LLM", icon: <Cpu size={16} />, status: "checking" },
    { name: "Backend API", icon: <Server size={16} />, status: "checking" },
    { name: "PostgreSQL", icon: <BarChart3 size={16} />, status: "checking" },
  ]);
  const [config, setConfig] = useState<ConfigSummary | null>(null);
  const [onboarded, setOnboarded] = useState<boolean | null>(null);
  const [skillCount, setSkillCount] = useState<number | null>(null);

  useEffect(() => {
    setOnboarded(localStorage.getItem("threatclaw_onboarded") === "true");

    // Check Ollama
    fetch("/api/ollama?url=http://ollama:11434")
      .then(r => r.json())
      .then(d => {
        const models = (d.models || []).map((m: { name: string }) => m.name);
        setServices(s => s.map(svc =>
          svc.name === "Ollama LLM"
            ? { ...svc, status: "ok" as const, detail: `${models.length} modèle(s)` }
            : svc
        ));
      })
      .catch(() => setServices(s => s.map(svc =>
        svc.name === "Ollama LLM" ? { ...svc, status: "down" as const, detail: "Non accessible" } : svc
      )));

    // Check Backend API + DB
    fetch("/api/tc/health")
      .then(r => r.json())
      .then(d => {
        setServices(s => s.map(svc => {
          if (svc.name === "Backend API") return { ...svc, status: "ok" as const, detail: `v${d.version || "?"}` };
          if (svc.name === "PostgreSQL") return { ...svc, status: d.database ? "ok" as const : "down" as const, detail: d.database ? "Connecté" : "Non connecté" };
          return svc;
        }));
      })
      .catch(() => {
        setServices(s => s.map(svc =>
          svc.name === "Backend API" || svc.name === "PostgreSQL"
            ? { ...svc, status: "down" as const, detail: "Core non démarré" }
            : svc
        ));
      });

    // Load config
    fetch("/api/tc/config").then(r => r.json()).then(d => setConfig(d)).catch(() => {
      try {
        const raw = localStorage.getItem("threatclaw_config");
        if (raw) setConfig(JSON.parse(raw));
      } catch { /* */ }
    });

    // Load skills count
    fetch("/api/tc/skills/catalog").then(r => r.json())
      .then(d => setSkillCount((d.skills || []).filter((s: { installed: boolean }) => s.installed).length))
      .catch(() => {});
  }, []);

  const activeChannels = config?.channels
    ? Object.entries(config.channels).filter(([, v]) => v.enabled).map(([k]) => k)
    : [];

  const permLabel: Record<string, string> = {
    READ_ONLY: "Observation",
    ALERT_ONLY: "Alertes",
    REMEDIATE_WITH_APPROVAL: "Remédiation supervisée",
    FULL_AUTO: "Automatisation complète",
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>
          Dashboard
        </h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
          Vue d{"'"}ensemble de votre agent de cybersécurité
        </p>
      </div>

      {/* Onboarding banner */}
      {onboarded === false && (
        <ChromeInsetCard glow style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-red)" }}>
                Configuration requise
              </div>
              <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginTop: "4px" }}>
                Lancez l{"'"}assistant pour configurer votre IA, vos canaux et votre niveau de sécurité.
              </div>
            </div>
            <ChromeButton onClick={() => window.location.href = "/setup"} variant="primary">
              <Settings size={14} /> Configurer <ArrowRight size={14} />
            </ChromeButton>
          </div>
        </ChromeInsetCard>
      )}

      {/* Services grid */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "12px" }}>
        Services
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "28px" }}>
        {services.map(svc => (
          <ChromeInsetCard key={svc.name}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div style={{
                width: "36px", height: "36px", borderRadius: "var(--tc-radius-md)",
                display: "flex", alignItems: "center", justifyContent: "center",
                background: svc.status === "ok" ? "rgba(48,160,80,0.08)" : svc.status === "down" ? "rgba(208,48,32,0.08)" : "var(--tc-input)",
                border: `1px solid ${svc.status === "ok" ? "rgba(48,160,80,0.15)" : svc.status === "down" ? "rgba(208,48,32,0.15)" : "var(--tc-input)"}`,
                color: svc.status === "ok" ? "#30a050" : svc.status === "down" ? "#d03020" : "var(--tc-text-muted)",
              }}>
                {svc.status === "checking" ? <Loader2 size={16} className="animate-spin" /> : svc.icon}
              </div>
              <div>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)" }}>{svc.name}</div>
                <div style={{
                  fontSize: "11px", marginTop: "2px",
                  color: svc.status === "ok" ? "#30a050" : svc.status === "down" ? "#d03020" : "var(--tc-text-muted)",
                }}>
                  {svc.status === "checking" ? "Vérification..." : svc.detail || (svc.status === "ok" ? "Opérationnel" : "Hors ligne")}
                </div>
              </div>
            </div>
          </ChromeInsetCard>
        ))}
      </div>

      {/* Config overview */}
      {(config || onboarded) && (
        <>
          <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "12px" }}>
            Configuration active
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "28px" }}>
            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <Cpu size={18} color="#d03020" />
                <div>
                  <div style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>IA Principale</div>
                  <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginTop: "2px" }}>
                    {config?.llm?.backend || "Non configuré"}
                  </div>
                  {config?.llm?.model && (
                    <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", fontFamily: "monospace", marginTop: "2px" }}>{config.llm.model}</div>
                  )}
                </div>
              </div>
            </ChromeInsetCard>

            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <Shield size={18} color="#d03020" />
                <div>
                  <div style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Sécurité</div>
                  <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginTop: "2px" }}>
                    {permLabel[config?.permissions || ""] || "Non configuré"}
                  </div>
                </div>
              </div>
            </ChromeInsetCard>

            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <MessageSquare size={18} color="#d03020" />
                <div>
                  <div style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Canaux</div>
                  <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginTop: "2px" }}>
                    {activeChannels.length > 0 ? activeChannels.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(", ") : "Aucun actif"}
                  </div>
                </div>
              </div>
            </ChromeInsetCard>

            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <Puzzle size={18} color="#d03020" />
                <div>
                  <div style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Skills</div>
                  <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginTop: "2px" }}>
                    {skillCount !== null ? `${skillCount} active(s)` : "—"}
                  </div>
                </div>
              </div>
            </ChromeInsetCard>
          </div>
        </>
      )}

      {/* Quick actions */}
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <ChromeButton onClick={() => window.location.href = "/skills"} variant="glass">
          <Puzzle size={14} /> Skills
        </ChromeButton>
        <ChromeButton onClick={() => window.location.href = "/agent"} variant="glass">
          <Activity size={14} /> Agent
        </ChromeButton>
        <ChromeButton onClick={() => window.location.href = "/setup"} variant="primary">
          <Settings size={14} /> Configuration <ArrowRight size={14} />
        </ChromeButton>
      </div>
    </div>
  );
}

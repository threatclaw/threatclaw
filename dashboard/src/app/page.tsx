"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  CheckCircle2, XCircle, Loader2, Settings, Puzzle, Activity,
  Cpu, MessageSquare, Shield, Database, Wifi,
} from "lucide-react";

interface ServiceStatus {
  name: string;
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
    { name: "Ollama", status: "checking" },
    { name: "Backend API", status: "checking" },
    { name: "PostgreSQL", status: "checking" },
  ]);
  const [config, setConfig] = useState<ConfigSummary | null>(null);
  const [onboarded, setOnboarded] = useState<boolean | null>(null);
  const [skillCount, setSkillCount] = useState<number | null>(null);

  useEffect(() => {
    setOnboarded(localStorage.getItem("threatclaw_onboarded") === "true");

    // Check Ollama
    fetch("/api/ollama?url=http://localhost:11434")
      .then(r => r.json())
      .then(d => {
        const models = (d.models || []).map((m: { name: string }) => m.name);
        setServices(s => s.map(svc =>
          svc.name === "Ollama"
            ? { ...svc, status: "ok" as const, detail: `${models.length} modèle(s): ${models.join(", ")}` }
            : svc
        ));
      })
      .catch(() => setServices(s => s.map(svc =>
        svc.name === "Ollama" ? { ...svc, status: "down" as const, detail: "Non accessible sur localhost:11434" } : svc
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
            ? { ...svc, status: "down" as const, detail: "Core ThreatClaw non démarré" }
            : svc
        ));
      });

    // Load config
    fetch("/api/tc/config")
      .then(r => r.json())
      .then(d => setConfig(d))
      .catch(() => {
        // Fallback localStorage
        try {
          const raw = localStorage.getItem("threatclaw_config");
          if (raw) setConfig(JSON.parse(raw));
        } catch { /* */ }
      });

    // Load skills count
    fetch("/api/tc/skills/catalog")
      .then(r => r.json())
      .then(d => setSkillCount((d.skills || []).filter((s: { installed: boolean }) => s.installed).length))
      .catch(() => {});
  }, []);

  const allOk = services.every(s => s.status === "ok");
  const anyChecking = services.some(s => s.status === "checking");

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
      {/* Onboarding banner */}
      {onboarded === false && (
        <ChromeInsetCard className="mb-4">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "12px", fontWeight: 800, color: "#903020" }}>
                Configuration requise
              </ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.6, marginTop: "2px" }}>
                Lancez l{"'"}assistant pour configurer votre IA, vos canaux et votre niveau de sécurité.
              </ChromeEmbossedText>
            </div>
            <ChromeButton onClick={() => window.location.href = "/setup"}>
              <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px" }}>
                <Settings size={12} /> Configurer
              </span>
            </ChromeButton>
          </div>
        </ChromeInsetCard>
      )}

      {/* Services status */}
      <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px", opacity: 0.5 }}>
        État des services
      </ChromeEmbossedText>
      <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "20px" }}>
        {services.map(svc => (
          <ChromeInsetCard key={svc.name}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              {svc.status === "checking" ? (
                <Loader2 size={14} className="animate-spin" color="#907060" />
              ) : svc.status === "ok" ? (
                <CheckCircle2 size={14} color="#2d6a40" />
              ) : (
                <XCircle size={14} color="#903020" />
              )}
              <div style={{ flex: 1 }}>
                <ChromeEmbossedText as="span" style={{ fontSize: "11px", fontWeight: 700 }}>
                  {svc.name}
                </ChromeEmbossedText>
              </div>
              <ChromeEmbossedText as="span" style={{ fontSize: "9px", opacity: 0.5 }}>
                {svc.detail || (svc.status === "checking" ? "Vérification..." : "")}
              </ChromeEmbossedText>
            </div>
          </ChromeInsetCard>
        ))}
      </div>

      {/* Config summary */}
      {(config || onboarded) && (
        <>
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px", opacity: 0.5 }}>
            Configuration
          </ChromeEmbossedText>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", marginBottom: "20px" }}>
            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Cpu size={14} color="#903020" />
                <div>
                  <ChromeEmbossedText as="div" style={{ fontSize: "8px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", opacity: 0.4 }}>IA Principale</ChromeEmbossedText>
                  <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 700 }}>
                    {config?.llm?.backend || "Non configuré"}
                  </ChromeEmbossedText>
                  {config?.llm?.model && (
                    <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.4, fontFamily: "monospace" }}>
                      {config.llm.model}
                    </ChromeEmbossedText>
                  )}
                </div>
              </div>
            </ChromeInsetCard>

            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Shield size={14} color="#903020" />
                <div>
                  <ChromeEmbossedText as="div" style={{ fontSize: "8px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", opacity: 0.4 }}>Niveau sécurité</ChromeEmbossedText>
                  <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 700 }}>
                    {permLabel[config?.permissions || ""] || config?.permissions || "Non configuré"}
                  </ChromeEmbossedText>
                </div>
              </div>
            </ChromeInsetCard>

            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <MessageSquare size={14} color="#903020" />
                <div>
                  <ChromeEmbossedText as="div" style={{ fontSize: "8px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", opacity: 0.4 }}>Canaux</ChromeEmbossedText>
                  <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 700 }}>
                    {activeChannels.length > 0 ? activeChannels.join(", ") : "Aucun"}
                  </ChromeEmbossedText>
                </div>
              </div>
            </ChromeInsetCard>

            <ChromeInsetCard>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Puzzle size={14} color="#903020" />
                <div>
                  <ChromeEmbossedText as="div" style={{ fontSize: "8px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", opacity: 0.4 }}>Skills</ChromeEmbossedText>
                  <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 700 }}>
                    {skillCount !== null ? `${skillCount} installée(s)` : "—"}
                  </ChromeEmbossedText>
                </div>
              </div>
            </ChromeInsetCard>
          </div>
        </>
      )}

      {/* Quick actions */}
      <ChromeInsetCard>
        <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: "12px", opacity: 0.5 }}>
          Actions
        </ChromeEmbossedText>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <ChromeButton onClick={() => window.location.href = "/skills"}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "10px" }}>
              <Puzzle size={12} /> Skills
            </span>
          </ChromeButton>
          <ChromeButton onClick={() => window.location.href = "/agent"}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "10px" }}>
              <Activity size={12} /> Agent
            </span>
          </ChromeButton>
          <ChromeButton onClick={() => window.location.href = "/setup"}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "10px" }}>
              <Settings size={12} /> Configuration
            </span>
          </ChromeButton>
        </div>
      </ChromeInsetCard>
    </div>
  );
}

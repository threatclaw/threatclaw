"use client";

import React, { useState, useEffect } from "react";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  CheckCircle2, Loader2, Settings, Puzzle, Activity,
  Cpu, MessageSquare, Shield, Server, ArrowRight,
  HardDrive, Clock, Brain, Database, Eye, Wifi,
  ChevronRight,
} from "lucide-react";

const labelCaps: React.CSSProperties = {
  fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)",
  textTransform: "uppercase", letterSpacing: "0.06em",
};

const metricBig: React.CSSProperties = {
  fontSize: "20px", fontWeight: 800, color: "var(--tc-text)", marginTop: "4px",
};

export default function HomePage() {
  const [services, setServices] = useState<{ name: string; icon: React.ReactNode; status: "ok" | "down" | "checking"; detail?: string }[]>([
    { name: "ThreatClaw Engine", icon: <Shield size={16} />, status: "checking" },
    { name: "ThreatClaw AI", icon: <Brain size={16} />, status: "checking" },
    { name: "Base de données", icon: <Database size={16} />, status: "checking" },
  ]);
  const [config, setConfig] = useState<any>(null);
  const [onboarded, setOnboarded] = useState<boolean | null>(null);
  const [situation, setSituation] = useState<any>(null);
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [lastCycle, setLastCycle] = useState<string | null>(null);

  useEffect(() => {
    setOnboarded(localStorage.getItem("threatclaw_onboarded") === "true");

    // Check Backend + DB
    fetch("/api/tc/health", { signal: AbortSignal.timeout(8000) })
      .then(r => r.json())
      .then(d => {
        setServices(s => s.map(svc => {
          if (svc.name === "ThreatClaw Engine") return { ...svc, status: "ok" as const, detail: `v${d.version || "?"}` };
          if (svc.name === "Base de données") return { ...svc, status: d.database ? "ok" as const : "down" as const, detail: d.database ? "PostgreSQL connecté" : "Non connecté" };
          return svc;
        }));
      })
      .catch(() => {
        setServices(s => s.map(svc =>
          svc.name === "ThreatClaw Engine" || svc.name === "Base de données"
            ? { ...svc, status: "down" as const, detail: "Service non démarré" }
            : svc
        ));
      });

    // Check Ollama models
    fetch("/api/ollama?url=http://ollama:11434", { signal: AbortSignal.timeout(8000) })
      .then(r => r.json())
      .then(d => {
        const models = (d.models || []).map((m: { name: string }) => m.name);
        setAiModels(models);
        setServices(s => s.map(svc =>
          svc.name === "ThreatClaw AI"
            ? { ...svc, status: models.length > 0 ? "ok" as const : "down" as const, detail: models.length > 0 ? `${models.length} modèle(s) chargé(s)` : undefined }
            : svc
        ));
      })
      .catch(() => setServices(s => s.map(svc =>
        svc.name === "ThreatClaw AI" ? { ...svc, status: "down" as const, detail: "Non accessible" } : svc
      )));

    // Load config
    fetch("/api/tc/config", { signal: AbortSignal.timeout(5000) }).then(r => r.json()).then(d => setConfig(d)).catch(() => {});

    // Load situation
    fetch("/api/tc/intelligence/situation", { signal: AbortSignal.timeout(5000) }).then(r => r.json()).then(d => {
      setSituation(d);
      if (d.computed_at) {
        const ago = Math.round((Date.now() - new Date(d.computed_at).getTime()) / 60000);
        setLastCycle(ago < 1 ? "< 1 min" : `${ago} min`);
      }
    }).catch(() => {});
  }, []);

  const activeChannels = config?.channels
    ? Object.entries(config.channels).filter(([, v]: any) => v.enabled).map(([k]: any) => k)
    : [];

  const score = situation?.global_score;
  const scoreColor = score == null ? "var(--tc-text-muted)" : score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const scoreLabel = score == null ? "En attente du premier cycle" : score >= 80 ? "Situation saine" : score >= 50 ? "Points d'attention" : "Situation dégradée";

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>Dashboard</h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>Vue d{"'"}ensemble de votre agent de cybersécurité</p>
      </div>

      {/* Onboarding banner */}
      {onboarded === false && (
        <NeuCard style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-red)" }}>Configuration requise</div>
              <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginTop: "4px" }}>Lancez l{"'"}assistant pour configurer votre infrastructure.</div>
            </div>
            <ChromeButton onClick={() => window.location.href = "/setup"} variant="primary">
              <Settings size={14} /> Configurer <ArrowRight size={14} />
            </ChromeButton>
          </div>
        </NeuCard>
      )}

      {/* ══ Score + Services ══ */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "12px", marginBottom: "20px" }}>
        <NeuCard>
          <div style={{ textAlign: "center" }}>
            <div style={labelCaps}>Score sécurité</div>
            <div style={{ fontSize: "42px", fontWeight: 900, color: scoreColor, margin: "8px 0 4px" }}>
              {score != null ? Math.round(score) : "—"}
            </div>
            <div style={{ fontSize: "10px", color: scoreColor }}>{scoreLabel}</div>
            {situation?.total_active_alerts > 0 && (
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "8px" }}>
                {situation.total_active_alerts} alerte(s) · {situation.assets?.length || 0} asset(s)
              </div>
            )}
          </div>
        </NeuCard>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px" }}>
          {services.map(svc => (
            <NeuCard key={svc.name} style={{ padding: "14px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <div style={{
                  width: "32px", height: "32px", borderRadius: "var(--tc-radius-sm)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: svc.status === "ok" ? "rgba(48,160,80,0.08)" : svc.status === "down" ? "rgba(208,48,32,0.08)" : "var(--tc-input)",
                  color: svc.status === "ok" ? "#30a050" : svc.status === "down" ? "#d03020" : "var(--tc-text-muted)",
                }}>
                  {svc.status === "checking" ? <Loader2 size={14} className="animate-spin" /> : svc.icon}
                </div>
                <div>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>{svc.name}</div>
                  <div style={{ fontSize: "10px", color: svc.status === "ok" ? "#30a050" : svc.status === "down" ? "#d03020" : "var(--tc-text-muted)" }}>
                    {svc.status === "checking" ? "Vérification..." : svc.detail || (svc.status === "ok" ? "Opérationnel" : "Hors ligne")}
                  </div>
                </div>
              </div>
            </NeuCard>
          ))}
        </div>
      </div>

      {/* ══ ThreatClaw Engine ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        ThreatClaw Engine
      </div>
      <NeuCard style={{ marginBottom: "20px", padding: "14px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#30a050", animation: "pulse 2s infinite" }} />
            <span style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>Agent autonome · Cycle toutes les 5 min</span>
          </div>
          <div style={{ display: "flex", gap: "16px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
            <span>Dernier cycle : {lastCycle ? `il y a ${lastCycle}` : "en attente"}</span>
          </div>
        </div>
      </NeuCard>

      {/* ══ ThreatClaw AI ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        ThreatClaw AI
      </div>
      <NeuCard style={{ marginBottom: "20px", padding: "14px 16px" }}>
        {aiModels.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {aiModels.map((m, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "11px" }}>
                <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#30a050" }} />
                <span style={{ fontFamily: "monospace", color: "var(--tc-text)", fontWeight: 600 }}>{m}</span>
                <span style={{ color: "var(--tc-text-muted)", fontSize: "9px" }}>Chargé</span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: "12px", color: "var(--tc-text-muted)" }}>Aucun modèle IA chargé</span>
            <button onClick={() => window.location.href = "/setup"} style={{
              background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
              padding: "4px 10px", fontSize: "10px", fontWeight: 600, cursor: "pointer", color: "var(--tc-red)", fontFamily: "inherit",
              display: "flex", alignItems: "center", gap: "4px",
            }}>
              Installer <ChevronRight size={10} />
            </button>
          </div>
        )}
      </NeuCard>

      {/* ══ Détection comportementale ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        Détection comportementale
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", marginBottom: "20px" }}>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Analyse comportementale</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#30a050", marginTop: "4px" }}>Active</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>Score toutes les 5 min</div>
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Détection DNS</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#30a050", marginTop: "4px" }}>Active</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>Domaines suspects</div>
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Entraînement</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-amber)", marginTop: "4px" }}>Baseline 14j</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>Retrain nocturne 03h00</div>
        </NeuCard>
      </div>

      {/* ══ Santé serveur ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        Infrastructure
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "12px", marginBottom: "20px" }}>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Sécurité</div>
          {config?.permissions ? (
            <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
              {config.permissions === "READ_ONLY" ? "Observation" : config.permissions === "ALERT_ONLY" ? "Alertes" : config.permissions === "REMEDIATE_WITH_APPROVAL" ? "Remédiation" : "Auto"}
            </div>
          ) : (
            <button onClick={() => window.location.href = "/setup"} style={{ background: "none", border: "none", padding: 0, cursor: "pointer", marginTop: "4px", fontSize: "12px", fontWeight: 700, color: "var(--tc-red)", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px" }}>
              Configurer <ChevronRight size={11} />
            </button>
          )}
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Canaux</div>
          {activeChannels.length > 0 ? (
            <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
              {activeChannels.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(", ")}
            </div>
          ) : (
            <button onClick={() => window.location.href = "/setup"} style={{ background: "none", border: "none", padding: 0, cursor: "pointer", marginTop: "4px", fontSize: "12px", fontWeight: 700, color: "var(--tc-red)", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px" }}>
              Configurer <ChevronRight size={11} />
            </button>
          )}
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Base de données</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#30a050", marginTop: "4px" }}>Opérationnel</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>PG16 + AGE + TimescaleDB</div>
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Disque</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>680 GB libre</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>sur /srv</div>
        </NeuCard>
      </div>

      {/* Quick actions */}
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <ChromeButton onClick={() => window.location.href = "/assets"} variant="glass"><Server size={14} /> Assets</ChromeButton>
        <ChromeButton onClick={() => window.location.href = "/skills"} variant="glass"><Puzzle size={14} /> Skills</ChromeButton>
        <ChromeButton onClick={() => window.location.href = "/setup"} variant="primary"><Settings size={14} /> Configuration <ArrowRight size={14} /></ChromeButton>
      </div>
    </div>
  );
}

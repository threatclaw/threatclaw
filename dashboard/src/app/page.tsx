"use client";

import React, { useState, useEffect } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { CpuCard } from "@/components/chrome/CpuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import OnboardingBanner from "@/components/chrome/OnboardingBanner";
import OnboardingLevelPicker from "@/components/chrome/OnboardingLevelPicker";
import OnboardingTour from "@/components/chrome/OnboardingTour";
import { useOnboarding } from "@/lib/useOnboarding";
import {
  CheckCircle2, Loader2, Settings, Puzzle, Activity,
  Cpu, MessageSquare, Shield, Server, ArrowRight,
  HardDrive, Clock, Brain, Database, Eye, Wifi,
  ChevronRight, Monitor,
} from "lucide-react";

const labelCaps: React.CSSProperties = {
  fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)",
  textTransform: "uppercase", letterSpacing: "0.06em",
};

const metricBig: React.CSSProperties = {
  fontSize: "20px", fontWeight: 800, color: "var(--tc-text)", marginTop: "4px",
};

export default function HomePage() {
  const locale = useLocale();
  const onboarding = useOnboarding();
  const [showLevelPicker, setShowLevelPicker] = useState(false);
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
  const [diskFree, setDiskFree] = useState<string | null>(null);
  const [dbStatus, setDbStatus] = useState<"ok" | "down" | "checking">("checking");
  const [mlStatus, setMlStatus] = useState<{ anomaly: string; dns: string; training: string; dataDays: number; modelTrained: boolean }>({ anomaly: "checking", dns: "checking", training: "checking", dataDays: 0, modelTrained: false });

  // Show level picker on first visit after onboarding (no level chosen yet)
  useEffect(() => {
    if (!onboarding.loading && onboarded !== false) {
      const hasChosenLevel = localStorage.getItem("tc-onboarding-level-chosen");
      if (!hasChosenLevel && !onboarding.dismissed) {
        setShowLevelPicker(true);
      }
    }
  }, [onboarding.loading, onboarded, onboarding.dismissed]);

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
    fetch("/api/ollama", { signal: AbortSignal.timeout(8000) })
      .then(r => r.json())
      .then(d => {
        const allModels = (d.models || []).map((m: { name: string }) => m.name);
        // Count any LLM model (threatclaw-*, qwen*, mistral*, llama*, etc.)
        const llmModels = allModels.filter((n: string) => !n.includes("embed") && !n.includes("nomic"));
        setAiModels(allModels);
        setServices(s => s.map(svc =>
          svc.name === "ThreatClaw AI"
            ? { ...svc, status: llmModels.length > 0 ? "ok" as const : "down" as const, detail: llmModels.length > 0 ? `${llmModels.length} modèle(s) disponible(s)` : undefined }
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

    // Real DB status from health check
    fetch("/api/tc/health", { signal: AbortSignal.timeout(5000) }).then(r => r.json()).then(d => {
      setDbStatus(d.database ? "ok" : "down");
    }).catch(() => setDbStatus("down"));

    // Real ML engine status from health endpoint heartbeat
    fetch("/api/tc/health", { signal: AbortSignal.timeout(5000) }).then(r => r.json()).then(d => {
      const ml = d.ml;
      if (ml && ml.alive) {
        const heartbeatAge = ml.timestamp ? (Date.now() - new Date(ml.timestamp).getTime()) / 1000 : 9999;
        const isAlive = heartbeatAge < 600; // ML scores every 5 min, allow 10 min margin
        const dataDays = ml.data_days || 0;
        const modelTrained = ml.model_trained === true;
        // Real state: inactive (engine down) → learning (collecting data) → active (model trained)
        const realState = !isAlive ? "inactive" : modelTrained ? "active" : "learning";
        setMlStatus({
          anomaly: realState,
          dns: realState,
          training: modelTrained ? "trained" : dataDays > 0 ? "learning" : "waiting",
          dataDays,
          modelTrained,
        });
      } else {
        setMlStatus({ anomaly: "inactive", dns: "inactive", training: "inactive", dataDays: 0, modelTrained: false });
      }
    }).catch(() => setMlStatus({ anomaly: "inactive", dns: "inactive", training: "inactive", dataDays: 0, modelTrained: false }));

    // Real disk space — from health endpoint
    fetch("/api/tc/health", { signal: AbortSignal.timeout(5000) }).then(r => r.json()).then(d => {
      if (d.disk_free) setDiskFree(d.disk_free);
    }).catch(() => {});
  }, []);

  const activeChannels = config?.channels
    ? Object.entries(config.channels).filter(([, v]: any) => v.enabled).map(([k]: any) => k)
    : [];

  const score = situation?.global_score;
  const scoreColor = score == null ? "var(--tc-text-muted)" : score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const scoreLabel = score == null ? tr("waitingFirstCycle", locale) : score >= 80 ? tr("situationHealthy", locale) : score >= 50 ? tr("situationWarning", locale) : tr("situationCritical", locale);

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>{tr("dashboard", locale)}</h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>{tr("dashboardSubtitle", locale)}</p>
      </div>

      {/* Onboarding banner */}
      {onboarded === false && (
        <NeuCard style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-red)" }}>{tr("configRequired", locale)}</div>
              <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginTop: "4px" }}>{tr("configRequiredDesc", locale)}</div>
            </div>
            <ChromeButton onClick={() => window.location.href = "/setup"} variant="primary">
              <Settings size={14} /> {tr("configure", locale)} <ArrowRight size={14} />
            </ChromeButton>
          </div>
        </NeuCard>
      )}

      {/* Onboarding progress checklist */}
      {!onboarding.loading && !onboarding.dismissed && onboarding.level !== "expert" && onboarding.completed < onboarding.total && (
        <OnboardingBanner
          steps={onboarding.steps}
          completed={onboarding.completed}
          total={onboarding.total}
          onDismiss={onboarding.dismiss}
        />
      )}

      {/* Level picker — shown once if no level set yet */}
      {showLevelPicker && (
        <OnboardingLevelPicker onSelect={(level) => {
          onboarding.setLevel(level);
          localStorage.setItem("tc-onboarding-level-chosen", "true");
          setShowLevelPicker(false);
        }} />
      )}

      {/* Contextual tour — Status page */}
      {!onboarding.loading && (
        <OnboardingTour
          tourId="status"
          locale={locale}
          level={onboarding.level}
          toursCompleted={onboarding.toursCompleted}
          onComplete={onboarding.markTourCompleted}
          steps={[
            { element: "[data-tour='score']", descKey: "tourStatusScore" },
            { element: "[data-tour='ml']", descKey: "tourStatusMl" },
            { element: "[data-tour='infra']", descKey: "tourStatusInfra" },
          ]}
        />
      )}

      {/* ══ Central Processor ══ */}
      <NeuCard accent="red" style={{ marginBottom: "20px", padding: "10px 16px" }}>
        <CpuCard
          score={score}
          scoreLabel={scoreLabel}
          version={services.find(s => s.name === "ThreatClaw Engine")?.detail || ""}
          services={[
            { name: "PostgreSQL", connected: dbStatus === "ok", color: "#3080d0", detail: "Base de données PG16" },
            { name: "AI", connected: aiModels.length > 0, color: "#9060d0", detail: `${aiModels.length} modèle(s)`, restartable: true },
            { name: "Intel. Engine", connected: services[0]?.status === "ok", color: "#d03020", detail: "Corrélation & scoring" },
            { name: "ML Engine", connected: services[0]?.status === "ok", color: "#d09020", detail: mlStatus.modelTrained ? (locale === "fr" ? "Modèle entraîné" : "Model trained") : mlStatus.dataDays > 0 ? (locale === "fr" ? `Apprentissage (${mlStatus.dataDays}/14j)` : `Learning (${mlStatus.dataDays}/14d)`) : (locale === "fr" ? "En attente de données" : "Waiting for data"), restartable: true },
            { name: "Skills", connected: services[0]?.status === "ok", color: "#06b6d4", detail: "49 skills" },
            { name: "Channels", connected: activeChannels.length > 0, color: "#30a050", detail: activeChannels.join(", ") || "Non configuré" },
            { name: "Logs", connected: dbStatus === "ok", color: "#f97316", detail: "Syslog + FluentBit" },
            { name: "Dashboard", connected: true, color: "#b0a8a0", detail: "Next.js frontend" },
          ]}
        />
      </NeuCard>

      {/* ══ Score + Services ══ */}
      <div data-tour="score" style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "12px", marginBottom: "20px" }}>
        <NeuCard accent="grid">
          <div style={{ textAlign: "center" }}>
            <div style={labelCaps}>{tr("securityScore", locale)}</div>
            <div style={{ fontSize: "42px", fontWeight: 900, color: scoreColor, margin: "8px 0 4px" }}>
              {score != null ? Math.round(score) : "—"}
            </div>
            {/* Heartbeat monitor */}
            {score != null && (
              <div style={{ position: "relative", width: "100%", height: "32px", overflow: "hidden", margin: "4px 0" }}>
                <svg viewBox="0 0 150 40" style={{ width: "100%", height: "100%" }} preserveAspectRatio="none">
                  <polyline
                    fill="none"
                    stroke={scoreColor}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points="0,20 20,20 25,20 30,10 35,30 40,5 45,35 50,20 55,20 75,20 80,20 85,12 90,28 95,8 100,32 105,20 110,20 130,20 150,20"
                  >
                    <animate attributeName="stroke-dasharray" from="0,300" to="300,0" dur="2.5s" repeatCount="indefinite" />
                  </polyline>
                </svg>
                <div style={{
                  position: "absolute", top: 0, right: 0, width: "100%", height: "100%",
                  background: `linear-gradient(to left, transparent 0%, var(--tc-neu-inner) 100%)`,
                  animation: "heartFadeIn 2.5s linear infinite",
                }} />
                <style>{`
                  @keyframes heartFadeIn {
                    0% { opacity: 1; }
                    50% { opacity: 0; }
                    100% { opacity: 0; }
                  }
                `}</style>
              </div>
            )}
            <div style={{ fontSize: "10px", color: scoreColor }}>{scoreLabel}</div>
            {situation?.total_active_alerts > 0 && (
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "8px" }}>
                {situation.total_active_alerts} alerte(s) · {situation.assets?.length || 0} asset(s)
              </div>
            )}
          </div>
        </NeuCard>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px" }}>
          {services.map(svc => {
            const isEngine = svc.name === "ThreatClaw Engine";
            const isAI = svc.name === "ThreatClaw AI";
            const statusColor = svc.status === "ok" ? "#30a050" : svc.status === "down" ? "#d03020" : "var(--tc-text-muted)";
            return (
              <NeuCard key={svc.name} accent={isEngine ? "dots" : isAI ? "purple" : "blue"} style={{ padding: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div style={{
                    width: "32px", height: "32px", borderRadius: isEngine ? "50%" : "var(--tc-radius-sm)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    background: svc.status === "ok" ? "rgba(48,160,80,0.08)" : svc.status === "down" ? "rgba(208,48,32,0.08)" : "var(--tc-input)",
                    color: statusColor, position: "relative", overflow: "hidden",
                  }}>
                    {svc.status === "checking" ? (
                      <Loader2 size={14} className="animate-spin" />
                    ) : isEngine && svc.status === "ok" ? (
                      /* Mini radar sweep */
                      <>
                        <div style={{ position: "absolute", width: "100%", height: "100%", borderRadius: "50%", border: "1px dashed rgba(48,160,80,0.25)" }} />
                        <div style={{ position: "absolute", width: "50%", height: "50%", borderRadius: "50%", border: "1px dashed rgba(48,160,80,0.2)" }} />
                        <div style={{
                          position: "absolute", top: "50%", left: "50%", width: "50%", height: "2px",
                          background: "linear-gradient(to right, #30a050, transparent)",
                          transformOrigin: "0 0",
                          animation: "radarSweep 2s linear infinite",
                        }} />
                        <div style={{ width: "3px", height: "3px", borderRadius: "50%", background: "#30a050", position: "relative", zIndex: 1 }} />
                      </>
                    ) : isAI && svc.status === "ok" ? (
                      /* AI wave dots */
                      <div style={{ display: "flex", gap: "2px", alignItems: "center" }}>
                        {[0, 1, 2, 3, 4].map(i => (
                          <div key={i} style={{
                            width: "3px", height: "3px", borderRadius: "50%", background: "#30a050",
                            animation: `aiDot 1.2s ease-in-out ${i * 0.15}s infinite`,
                          }} />
                        ))}
                      </div>
                    ) : svc.icon}
                  </div>
                  <div>
                    <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>{svc.name}</div>
                    <div style={{ fontSize: "10px", color: statusColor }}>
                      {svc.status === "checking" ? tr("checking", locale) : svc.detail || (svc.status === "ok" ? tr("operational", locale) : tr("offline", locale))}
                    </div>
                  </div>
                </div>
              </NeuCard>
            );
          })}
        </div>
        <style>{`
          @keyframes radarSweep {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          @keyframes aiDot {
            0%, 100% { transform: translateY(0); opacity: 0.4; }
            50% { transform: translateY(-4px); opacity: 1; }
          }
        `}</style>
      </div>

      {/* ══ ThreatClaw Engine ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        ThreatClaw Engine
      </div>
      <NeuCard accent="scan" style={{ marginBottom: "20px", padding: "14px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#30a050", animation: "pulse 2s infinite" }} />
            <span style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>{tr("agentAutonomous", locale)}</span>
          </div>
          <div style={{ display: "flex", gap: "16px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
            <span>{tr("lastCycle", locale)} : {lastCycle ? `${lastCycle} ${tr("ago", locale)}` : tr("waiting", locale)}</span>
          </div>
        </div>
      </NeuCard>

      {/* ══ ThreatClaw Agent ══ */}
      <NeuCard accent="blue" style={{ marginBottom: "20px", padding: "14px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <Monitor size={16} color="var(--tc-blue)" />
            <div>
              <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>ThreatClaw Agent</div>
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "1px" }}>
                {locale === "fr"
                  ? "Installez l'agent sur vos machines pour l'inventaire logiciel, la détection de menaces et le suivi temps réel."
                  : "Install the agent on your endpoints for software inventory, threat detection and real-time monitoring."}
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: "6px" }}>
            <button onClick={() => { navigator.clipboard.writeText("curl -fsSL get.threatclaw.io/agent | sudo bash"); }}
              className="tc-btn-embossed" style={{ fontSize: "9px", padding: "5px 10px" }}>
              {locale === "fr" ? "Copier la commande" : "Copy command"}
            </button>
          </div>
        </div>
        <div style={{ marginTop: "8px", padding: "6px 10px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-neu-inner)", fontFamily: "monospace", fontSize: "10px", color: "var(--tc-blue)", userSelect: "all" }}>
          curl -fsSL get.threatclaw.io/agent | sudo bash
        </div>
      </NeuCard>

      {/* ══ Moteurs ThreatClaw ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        {locale === "fr" ? "Moteurs de détection" : "Detection Engines"}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "8px", marginBottom: "20px" }}>
        {[
          { name: "Intelligence Engine", detail: locale === "fr" ? "Corrélation & scoring" : "Correlation & scoring", active: services[0]?.status === "ok", color: "#d03020" },
          { name: "Sigma Engine", detail: locale === "fr" ? "Règles de détection" : "Detection rules", active: services[0]?.status === "ok", color: "#9060d0" },
          { name: "Bloom Filter", detail: locale === "fr" ? "IoC temps réel" : "Real-time IoC", active: services[0]?.status === "ok", color: "#06b6d4" },
          { name: "NDR (JA3/Beacon/TLS)", detail: locale === "fr" ? "Analyse réseau Zeek" : "Zeek network analysis", active: services[0]?.status === "ok", color: "#f97316" },
          { name: "ML Engine", detail: mlStatus.modelTrained ? (locale === "fr" ? "Modèle entraîné" : "Model trained") : (locale === "fr" ? "En apprentissage" : "Learning"), active: mlStatus.anomaly !== "inactive", color: "#d09020" },
          { name: "Graph Intelligence", detail: locale === "fr" ? "STIX 2.1 + corrélation" : "STIX 2.1 + correlation", active: services[0]?.status === "ok", color: "#30a050" },
        ].map(engine => (
          <NeuCard key={engine.name} style={{ padding: "10px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <div style={{ width: "6px", height: "6px", borderRadius: "50%", flexShrink: 0,
                background: engine.active ? engine.color : "var(--tc-text-faint)",
                boxShadow: engine.active ? `0 0 6px ${engine.color}60` : "none" }} />
              <div>
                <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>{engine.name}</div>
                <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "1px" }}>{engine.detail}</div>
              </div>
            </div>
          </NeuCard>
        ))}
      </div>

      {/* ══ Détection comportementale ══ */}
      <div data-tour="ml" style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        {tr("behavioralDetection", locale)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", marginBottom: "20px" }}>
        <NeuCard accent="amber" style={{ padding: "14px", opacity: mlStatus.training === "inactive" ? 0.5 : 1, transition: "opacity 0.3s" }}>
          <div style={labelCaps}>{tr("training", locale)}</div>
          {(() => {
            const days = mlStatus.dataDays;
            const target = 14;
            const pct = Math.min(100, Math.round((days / target) * 100));
            const remaining = Math.max(0, target - days);
            const trained = mlStatus.modelTrained;
            const trainingState = mlStatus.training;
            const color = trained ? "#30a050" : days > 0 ? "var(--tc-amber)" : "var(--tc-text-muted)";
            return (
              <>
                <div style={{ fontSize: "12px", fontWeight: 700, color, marginTop: "4px" }}>
                  {trainingState === "checking" ? tr("checking", locale) :
                   trainingState === "trained" ? tr("trainedOperational", locale) :
                   trainingState === "learning" ? `${tr("learningProgress", locale)} ${days}/${target}${tr("days", locale)}` :
                   trainingState === "waiting" ? tr("waitingForLogs", locale) : tr("inactive", locale)}
                </div>
                {trainingState !== "inactive" && (
                  <>
                    <div style={{ width: "100%", height: "4px", borderRadius: "2px", background: "var(--tc-input)", marginTop: "6px", overflow: "hidden" }}>
                      <div style={{
                        width: `${pct}%`, height: "100%", borderRadius: "2px",
                        background: trained ? "#30a050" : "var(--tc-amber)",
                        transition: "width 0.5s ease",
                      }} />
                    </div>
                    <div style={{ fontSize: "8px", color: "var(--tc-text-muted)", marginTop: "3px", display: "flex", justifyContent: "space-between" }}>
                      <span>{trained ? tr("retrainNightly", locale) : days === 0 ? tr("connectLogSource", locale) : `${remaining}${tr("daysRemaining", locale)}`}</span>
                      <span style={{ fontWeight: 700 }}>{pct}%</span>
                    </div>
                  </>
                )}
                {trainingState === "inactive" && (
                  <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "4px" }}>
                    {tr("waitingForMl", locale)}
                  </div>
                )}
              </>
            );
          })()}
        </NeuCard>
        <NeuCard accent="hex" style={{ padding: "14px", opacity: mlStatus.anomaly === "inactive" ? 0.5 : 1, transition: "opacity 0.3s" }}>
          <div style={labelCaps}>{tr("behavioralAnalysis", locale)}</div>
          <div style={{ fontSize: "12px", fontWeight: 700, marginTop: "4px",
            color: mlStatus.anomaly === "active" ? "#30a050" : mlStatus.anomaly === "learning" ? "var(--tc-amber)" : mlStatus.anomaly === "checking" ? "var(--tc-text-muted)" : "var(--tc-text-faint)" }}>
            {mlStatus.anomaly === "active" ? tr("active", locale) : mlStatus.anomaly === "learning" ? tr("learning", locale) : mlStatus.anomaly === "checking" ? tr("checking", locale) : tr("inactive", locale)}
          </div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
            {mlStatus.anomaly === "active" ? tr("scoreEvery5min", locale) : mlStatus.anomaly === "learning" ? `${tr("activeIn", locale)} ${Math.max(0, 14 - mlStatus.dataDays)}${tr("days", locale)}` : mlStatus.training !== "trained" ? tr("waitingForTraining", locale) : tr("waitingForMl", locale)}
          </div>
        </NeuCard>
        <NeuCard accent="rings" style={{ padding: "14px", opacity: mlStatus.dns === "inactive" ? 0.5 : 1, transition: "opacity 0.3s" }}>
          <div style={labelCaps}>{tr("dnsDetection", locale)}</div>
          <div style={{ fontSize: "12px", fontWeight: 700, marginTop: "4px",
            color: mlStatus.dns === "active" ? "#30a050" : mlStatus.dns === "learning" ? "var(--tc-amber)" : mlStatus.dns === "checking" ? "var(--tc-text-muted)" : "var(--tc-text-faint)" }}>
            {mlStatus.dns === "active" ? tr("active", locale) : mlStatus.dns === "learning" ? tr("learning", locale) : mlStatus.dns === "checking" ? tr("checking", locale) : tr("inactive", locale)}
          </div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
            {mlStatus.dns === "active" ? tr("suspiciousDomains", locale) : mlStatus.dns === "learning" ? `${tr("activeIn", locale)} ${Math.max(0, 14 - mlStatus.dataDays)}${tr("days", locale)}` : mlStatus.training !== "trained" ? tr("waitingForTraining", locale) : tr("waitingForMl", locale)}
          </div>
        </NeuCard>
      </div>

      {/* ══ Santé serveur ══ */}
      <div data-tour="infra" style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        {tr("infrastructure", locale)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "12px", marginBottom: "20px" }}>
        <NeuCard accent="grid" style={{ padding: "14px" }}>
          <div style={labelCaps}>{tr("security", locale)}</div>
          {config?.permissions ? (
            <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
              {config.permissions === "READ_ONLY" ? (locale === "fr" ? "Observation" : "Observe") : config.permissions === "ALERT_ONLY" ? (locale === "fr" ? "Alertes" : "Alerts") : config.permissions === "REMEDIATE_WITH_APPROVAL" ? (locale === "fr" ? "Remédiation" : "Remediate") : "Auto"}
            </div>
          ) : (
            <button onClick={() => window.location.href = "/setup"} style={{ background: "none", border: "none", padding: 0, cursor: "pointer", marginTop: "4px", fontSize: "12px", fontWeight: 700, color: "var(--tc-red)", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px" }}>
              {tr("configure", locale)} <ChevronRight size={11} />
            </button>
          )}
        </NeuCard>
        <NeuCard accent="blue" style={{ padding: "14px" }}>
          <div style={labelCaps}>{tr("channels", locale)}</div>
          {activeChannels.length > 0 ? (
            <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
              {activeChannels.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(", ")}
            </div>
          ) : (
            <button onClick={() => window.location.href = "/setup"} style={{ background: "none", border: "none", padding: 0, cursor: "pointer", marginTop: "4px", fontSize: "12px", fontWeight: 700, color: "var(--tc-red)", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px" }}>
              {tr("configure", locale)} <ChevronRight size={11} />
            </button>
          )}
        </NeuCard>
        <NeuCard accent="green" style={{ padding: "14px" }}>
          <div style={labelCaps}>{tr("database", locale)}</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: dbStatus === "ok" ? "#30a050" : dbStatus === "checking" ? "var(--tc-text-muted)" : "#d03020", marginTop: "4px" }}>
            {dbStatus === "ok" ? (locale === "fr" ? "Opérationnel" : "Operational") : dbStatus === "checking" ? (locale === "fr" ? "Vérification..." : "Checking...") : (locale === "fr" ? "Non connecté" : "Not connected")}
          </div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>PG16 + AGE + TimescaleDB</div>
        </NeuCard>
        <NeuCard accent="dots" style={{ padding: "14px" }}>
          <div style={labelCaps}>{tr("disk", locale)}</div>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>{diskFree || "—"}</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{locale === "fr" ? "sur /srv" : "on /srv"}</div>
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

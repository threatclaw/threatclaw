"use client";

import React, { useState, useEffect } from "react";
import { ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  CheckCircle2, XCircle, Loader2, Settings, Puzzle, Activity,
  Cpu, MessageSquare, Shield, Wifi, Server, ArrowRight, BarChart3,
  HardDrive, MemoryStick, Clock, Brain, AlertTriangle, TrendingUp,
  Database, Zap,
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

interface ServerStats {
  disk_used_gb?: number;
  disk_total_gb?: number;
  disk_percent?: number;
  memory_used_mb?: number;
  memory_total_mb?: number;
  memory_percent?: number;
  cpu_count?: number;
  uptime_hours?: number;
  load_avg?: number;
}

interface MlStatus {
  last_training?: string;
  last_scoring?: string;
  assets_scored?: number;
  anomalies_detected?: number;
  dga_suspicious?: number;
  model_exists?: boolean;
  baseline_days?: number;
}

const labelCaps: React.CSSProperties = {
  fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)",
  textTransform: "uppercase", letterSpacing: "0.06em",
};

const metricVal: React.CSSProperties = {
  fontSize: "20px", fontWeight: 800, color: "var(--tc-text)", marginTop: "2px",
};

export default function HomePage() {
  const [services, setServices] = useState<ServiceStatus[]>([
    { name: "Ollama LLM", icon: <Cpu size={16} />, status: "checking" },
    { name: "Backend API", icon: <Server size={16} />, status: "checking" },
    { name: "PostgreSQL", icon: <Database size={16} />, status: "checking" },
  ]);
  const [config, setConfig] = useState<ConfigSummary | null>(null);
  const [onboarded, setOnboarded] = useState<boolean | null>(null);
  const [skillCount, setSkillCount] = useState<number | null>(null);
  const [serverStats, setServerStats] = useState<ServerStats>({});
  const [mlStatus, setMlStatus] = useState<MlStatus>({});
  const [situation, setSituation] = useState<any>(null);

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
    fetch("/api/tc/config").then(r => r.json()).then(d => setConfig(d)).catch(() => {});

    // Load skills count
    fetch("/api/tc/skills/catalog").then(r => r.json())
      .then(d => setSkillCount((d.skills || []).filter((s: any) => s.installed).length))
      .catch(() => {});

    // Load intelligence situation
    fetch("/api/tc/intelligence/situation").then(r => r.json()).then(d => setSituation(d)).catch(() => {});

    // Load ML status
    fetch("/api/tc/config").then(r => r.json()).then(() => {
      // Read ML scores count from settings
      fetch("/api/tc/assets/counts").then(r => r.json()).then(d => {
        setMlStatus(prev => ({ ...prev, assets_scored: d.total || 0 }));
      }).catch(() => {});
    }).catch(() => {});

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

  const score = situation?.global_score;
  const scoreColor = score == null ? "var(--tc-text-muted)" : score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";

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
        <NeuCard style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-red)" }}>Configuration requise</div>
              <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginTop: "4px" }}>
                Lancez l{"'"}assistant pour configurer votre IA, vos canaux et votre niveau de sécurité.
              </div>
            </div>
            <ChromeButton onClick={() => window.location.href = "/setup"} variant="primary">
              <Settings size={14} /> Configurer <ArrowRight size={14} />
            </ChromeButton>
          </div>
        </NeuCard>
      )}

      {/* ══ Security Score + Services ══ */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "12px", marginBottom: "20px" }}>
        {/* Security Score */}
        <NeuCard>
          <div style={{ textAlign: "center" }}>
            <div style={labelCaps}>Score Sécurité</div>
            <div style={{ fontSize: "42px", fontWeight: 900, color: scoreColor, margin: "8px 0 4px" }}>
              {score != null ? `${Math.round(score)}` : "—"}
            </div>
            <div style={{ fontSize: "10px", color: scoreColor }}>
              {score == null ? "Pas encore calculé" : score >= 80 ? "Situation saine" : score >= 50 ? "Points d'attention" : "Situation dégradée"}
            </div>
            {situation?.total_active_alerts > 0 && (
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "8px" }}>
                {situation.total_active_alerts} alerte(s) · {situation.assets?.length || 0} asset(s) à risque
              </div>
            )}
          </div>
        </NeuCard>

        {/* Services */}
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
                  <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>{svc.name}</div>
                  <div style={{
                    fontSize: "10px",
                    color: svc.status === "ok" ? "#30a050" : svc.status === "down" ? "#d03020" : "var(--tc-text-muted)",
                  }}>
                    {svc.status === "checking" ? "Vérification..." : svc.detail || (svc.status === "ok" ? "OK" : "Hors ligne")}
                  </div>
                </div>
              </div>
            </NeuCard>
          ))}
        </div>
      </div>

      {/* ══ Server Health ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        Santé serveur
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "20px" }}>
        <ServerStatCard icon={<HardDrive size={16} />} label="Disque" value="680 GB" detail="libre sur /srv" color="#3080d0" />
        <ServerStatCard icon={<MemoryStick size={16} />} label="Mémoire" value="—" detail="utilisation" color="#9060d0" />
        <ServerStatCard icon={<Cpu size={16} />} label="CPU" value="—" detail="charge moyenne" color="#d09020" />
        <ServerStatCard icon={<Clock size={16} />} label="Uptime" value="—" detail="depuis le démarrage" color="#30a050" />
      </div>

      {/* ══ ML Engine Status ══ */}
      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
        Machine Learning
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "20px" }}>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Modèle</div>
          <div style={{ fontSize: "13px", fontWeight: 700, color: "#30a050", marginTop: "4px" }}>Isolation Forest</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>Entraîné · score 5 min</div>
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Assets scorés</div>
          <div style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", marginTop: "4px" }}>
            {mlStatus.assets_scored ?? "—"}
          </div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>sur la dernière période</div>
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>DGA Detector</div>
          <div style={{ fontSize: "13px", fontWeight: 700, color: "#30a050", marginTop: "4px" }}>Random Forest</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>Analyse DNS active</div>
        </NeuCard>
        <NeuCard style={{ padding: "14px" }}>
          <div style={labelCaps}>Baseline</div>
          <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-amber)", marginTop: "4px" }}>14 jours</div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>Retrain nocturne 03h00</div>
        </NeuCard>
      </div>

      {/* ══ Config overview ══ */}
      {(config || onboarded) && (
        <>
          <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
            Configuration
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "12px", marginBottom: "20px" }}>
            <NeuCard style={{ padding: "14px" }}>
              <div style={labelCaps}>IA Principale</div>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
                {config?.llm?.backend || "Non configuré"}
              </div>
              {config?.llm?.model && <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontFamily: "monospace", marginTop: "2px" }}>{config.llm.model}</div>}
            </NeuCard>
            <NeuCard style={{ padding: "14px" }}>
              <div style={labelCaps}>Sécurité</div>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
                {permLabel[config?.permissions || ""] || "Non configuré"}
              </div>
            </NeuCard>
            <NeuCard style={{ padding: "14px" }}>
              <div style={labelCaps}>Canaux</div>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
                {activeChannels.length > 0 ? activeChannels.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(", ") : "Aucun"}
              </div>
            </NeuCard>
            <NeuCard style={{ padding: "14px" }}>
              <div style={labelCaps}>Skills</div>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", marginTop: "4px" }}>
                {skillCount !== null ? `${skillCount} active(s)` : "—"}
              </div>
            </NeuCard>
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

function ServerStatCard({ icon, label, value, detail, color }: {
  icon: React.ReactNode; label: string; value: string; detail: string; color: string;
}) {
  return (
    <NeuCard style={{ padding: "14px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
        <span style={{ color }}>{icon}</span>
        <span style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</span>
      </div>
      <div style={{ fontSize: "18px", fontWeight: 800, color: "var(--tc-text)" }}>{value}</div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{detail}</div>
    </NeuCard>
  );
}

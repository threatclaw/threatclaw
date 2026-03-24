"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  Play, Loader2, CheckCircle2, XCircle, Shield, AlertTriangle,
  Zap, Bug, Wifi, Server, RefreshCw, Terminal,
} from "lucide-react";

interface Scenario {
  id: string;
  name: string;
  description: string;
  severity: string;
  category: string;
  estimated_duration: string;
}

interface RunResult {
  ok: boolean;
  scenario: string;
  status: string;
  message: string;
}

const SEVERITY_ICONS: Record<string, { icon: React.ReactNode; color: string }> = {
  CRITICAL: { icon: <Zap size={16} />, color: "#e84040" },
  HIGH: { icon: <AlertTriangle size={16} />, color: "#d07020" },
  MEDIUM: { icon: <Shield size={16} />, color: "var(--tc-amber)" },
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  "Attaque active": <Terminal size={14} />,
  "Exploitation CVE": <Bug size={14} />,
  "Phishing": <Wifi size={14} />,
  "Kill chain": <Zap size={14} />,
  "Malware / C2": <Server size={14} />,
  "Kill chain complète": <Zap size={14} />,
};

export default function TestPage() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { status: string; message: string; time: string }>>({});
  const [situation, setSituation] = useState<{ global_score?: number; notification_level?: string; open_findings?: number; active_alerts?: number } | null>(null);

  useEffect(() => {
    fetch("/api/tc/test/scenarios")
      .then(r => r.json())
      .then(d => { setScenarios(d.scenarios || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const refreshSituation = async () => {
    try {
      const res = await fetch("/api/tc/intelligence/situation");
      const d = await res.json();
      setSituation(d);
    } catch { /* */ }
  };

  useEffect(() => {
    refreshSituation();
    const t = setInterval(refreshSituation, 10000);
    return () => clearInterval(t);
  }, []);

  const runScenario = async (id: string) => {
    setRunning(id);
    setResults(prev => ({ ...prev, [id]: { status: "running", message: "Injection des données dans le pipeline...", time: new Date().toLocaleTimeString("fr-FR") } }));

    try {
      const res = await fetch(`/api/tc/test/run/${id}?notify=true`, { method: "POST" });
      const data: RunResult = await res.json();
      setResults(prev => ({
        ...prev,
        [id]: {
          status: data.ok ? "success" : "error",
          message: data.message,
          time: new Date().toLocaleTimeString("fr-FR"),
        },
      }));
    } catch (e) {
      setResults(prev => ({
        ...prev,
        [id]: { status: "error", message: "Erreur réseau", time: new Date().toLocaleTimeString("fr-FR") },
      }));
    }

    setRunning(null);

    // Refresh situation after 5s (time for intelligence cycle)
    setTimeout(refreshSituation, 5000);
    setTimeout(refreshSituation, 15000);
    setTimeout(refreshSituation, 30000);
  };

  if (loading) return (
    <ChromeInsetCard>
      <div style={{ textAlign: "center", padding: "32px" }}>
        <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 12px", color: "var(--tc-red)" }} />
        <div style={{ fontSize: "13px", color: "#5a534e" }}>Chargement des scénarios...</div>
      </div>
    </ChromeInsetCard>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>
          Simulation & Tests
        </h1>
        <p style={{ fontSize: "13px", color: "#5a534e", margin: "4px 0 0" }}>
          Scénarios de test réalistes — injectent des vrais logs/findings/alertes dans le pipeline
        </p>
      </div>

      {/* Current situation */}
      {situation && situation.global_score !== undefined && (
        <ChromeInsetCard style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", gap: "20px", alignItems: "center" }}>
            <div style={{ textAlign: "center" }}>
              <div style={{
                fontSize: "32px", fontWeight: 800,
                color: (situation.global_score ?? 100) >= 70 ? "#30a050" : (situation.global_score ?? 100) >= 40 ? "#d09020" : "#d03020",
              }}>
                {Math.round(situation.global_score ?? 100)}
              </div>
              <div style={{ fontSize: "10px", color: "#5a534e", textTransform: "uppercase" }}>Score</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--tc-text)", marginBottom: "4px" }}>
                Situation : <span style={{
                  color: situation.notification_level === "silence" ? "#30a050" : situation.notification_level === "digest" ? "#3080d0" : "#d03020",
                }}>{situation.notification_level || "silence"}</span>
              </div>
              <div style={{ fontSize: "12px", color: "#5a534e" }}>
                {situation.open_findings || 0} findings — {situation.active_alerts || 0} alertes
              </div>
            </div>
            <ChromeButton onClick={refreshSituation} variant="glass">
              <RefreshCw size={14} /> Rafraîchir
            </ChromeButton>
          </div>
        </ChromeInsetCard>
      )}

      {/* Scenarios */}
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {scenarios.map(s => {
          const sev = SEVERITY_ICONS[s.severity] || SEVERITY_ICONS.HIGH;
          const catIcon = CATEGORY_ICONS[s.category] || <Shield size={14} />;
          const result = results[s.id];
          const isRunning = running === s.id;

          return (
            <ChromeInsetCard key={s.id} style={{
              borderLeft: `3px solid ${sev.color}`,
              borderRadius: "var(--tc-radius-card)",
            }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}>
                {/* Icon */}
                <div style={{
                  width: "44px", height: "44px", borderRadius: "var(--tc-radius-card)", flexShrink: 0,
                  background: `${sev.color}12`, border: `1px solid ${sev.color}30`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color: sev.color,
                }}>
                  {sev.icon}
                </div>

                {/* Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px", flexWrap: "wrap" }}>
                    <span style={{ fontSize: "15px", fontWeight: 700, color: "var(--tc-text)" }}>{s.name}</span>
                    <span style={{
                      fontSize: "9px", fontWeight: 600, padding: "2px 6px", borderRadius: "4px",
                      background: `${sev.color}12`, color: sev.color, border: `1px solid ${sev.color}30`,
                    }}>{s.severity}</span>
                    <span style={{
                      fontSize: "9px", color: "#5a534e", display: "flex", alignItems: "center", gap: "3px",
                    }}>{catIcon} {s.category}</span>
                  </div>
                  <div style={{ fontSize: "12px", color: "#7a7470", lineHeight: 1.5, marginBottom: "8px" }}>
                    {s.description}
                  </div>

                  {/* Result */}
                  {result && (
                    <div style={{
                      fontSize: "12px", padding: "8px 12px", borderRadius: "var(--tc-radius-input)", marginBottom: "8px",
                      background: result.status === "success" ? "rgba(48,160,80,0.06)" : result.status === "running" ? "rgba(48,128,208,0.06)" : "rgba(208,48,32,0.06)",
                      border: `1px solid ${result.status === "success" ? "rgba(48,160,80,0.15)" : result.status === "running" ? "rgba(48,128,208,0.15)" : "rgba(208,48,32,0.15)"}`,
                      color: result.status === "success" ? "#30a050" : result.status === "running" ? "#3080d0" : "#d03020",
                      display: "flex", alignItems: "center", gap: "8px",
                    }}>
                      {result.status === "success" ? <CheckCircle2 size={14} /> : result.status === "running" ? <Loader2 size={14} className="animate-spin" /> : <XCircle size={14} />}
                      <span style={{ flex: 1 }}>{result.message}</span>
                      <span style={{ fontSize: "10px", color: "#5a534e" }}>{result.time}</span>
                    </div>
                  )}
                </div>

                {/* Run button */}
                <ChromeButton
                  onClick={() => runScenario(s.id)}
                  disabled={isRunning}
                  variant="primary"
                >
                  {isRunning ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                  {isRunning ? "En cours..." : "Lancer"}
                </ChromeButton>
              </div>
            </ChromeInsetCard>
          );
        })}
      </div>

      {/* Info */}
      <ChromeInsetCard style={{ marginTop: "20px" }}>
        <div style={{ fontSize: "12px", color: "#5a534e", lineHeight: 1.7 }}>
          <strong style={{ color: "var(--tc-text)" }}>Comment ça marche</strong>
          <br /><br />
          Chaque scénario injecte des <strong style={{ color: "var(--tc-text)" }}>vrais logs</strong> dans la table PostgreSQL (comme Fluent Bit),
          crée des <strong style={{ color: "var(--tc-text)" }}>vrais findings</strong> et des <strong style={{ color: "var(--tc-text)" }}>vraies alertes Sigma</strong>.
          <br /><br />
          {"L'Intelligence Engine traite ensuite ces données exactement comme en production : extraction d'IoCs, enrichissement (EPSS, GreyNoise, IPinfo), calcul du score, et notification au RSSI si nécessaire."}
          <br /><br />
          Les données de test restent dans la base et sont visibles dans Findings et Alertes.
          Tous les IoCs utilisés sont <strong style={{ color: "var(--tc-red)" }}>réels</strong> (IPs Tor connues, CVEs exploitées, etc.).
        </div>
      </ChromeInsetCard>
    </div>
  );
}

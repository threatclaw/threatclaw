"use client";

import React, { useState, useEffect } from "react";
import { NeuCard as ChromeInsetCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  Play, Loader2, CheckCircle2, XCircle, Shield, AlertTriangle,
  Zap, Bug, Wifi, Server, RefreshCw, Terminal, Trash2, Info,
} from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

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
  const locale = useLocale();
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { status: string; message: string; time: string }>>({});
  const [situation, setSituation] = useState<{ global_score?: number; notification_level?: string; open_findings?: number; active_alerts?: number } | null>(null);
  const [demoStatus, setDemoStatus] = useState<{ demo_findings: number; demo_alerts: number; total: number }>({ demo_findings: 0, demo_alerts: 0, total: 0 });
  const [cleaning, setCleaning] = useState(false);

  useEffect(() => {
    fetch("/api/tc/test/scenarios")
      .then(r => r.json())
      .then(d => { setScenarios(d.scenarios || []); setLoading(false); })
      .catch(() => setLoading(false));
    refreshDemoStatus();
  }, []);

  const refreshDemoStatus = async () => {
    try {
      const res = await fetch("/api/tc/test/status");
      const d = await res.json();
      setDemoStatus(d);
    } catch { /* */ }
  };

  const refreshSituation = async () => {
    try {
      const res = await fetch("/api/tc/intelligence/situation");
      const d = await res.json();
      setSituation(d);
    } catch { /* */ }
  };

  useEffect(() => {
    refreshSituation();
    const t = setInterval(() => { refreshSituation(); refreshDemoStatus(); }, 10000);
    return () => clearInterval(t);
  }, []);

  const cleanupDemo = async () => {
    setCleaning(true);
    try {
      const res = await fetch("/api/tc/test/cleanup", { method: "POST" });
      const d = await res.json();
      setResults({});
      await refreshDemoStatus();
      await refreshSituation();
    } catch { /* */ }
    setCleaning(false);
  };

  const runScenario = async (id: string) => {
    setRunning(id);
    setResults(prev => ({ ...prev, [id]: { status: "running", message: locale === "fr" ? "Injection des donnees dans le pipeline..." : "Injecting data into pipeline...", time: new Date().toLocaleTimeString(locale === "fr" ? "fr-FR" : "en-US") } }));

    try {
      const res = await fetch(`/api/tc/test/run/${id}?notify=true`, { method: "POST" });
      const data: RunResult = await res.json();
      setResults(prev => ({
        ...prev,
        [id]: {
          status: data.ok ? "success" : "error",
          message: data.message,
          time: new Date().toLocaleTimeString(locale === "fr" ? "fr-FR" : "en-US"),
        },
      }));
    } catch (e) {
      setResults(prev => ({
        ...prev,
        [id]: { status: "error", message: locale === "fr" ? "Erreur reseau" : "Network error", time: new Date().toLocaleTimeString(locale === "fr" ? "fr-FR" : "en-US") },
      }));
    }

    setRunning(null);
    setTimeout(refreshDemoStatus, 5000);
    setTimeout(refreshSituation, 5000);
    setTimeout(refreshDemoStatus, 15000);
    setTimeout(refreshSituation, 15000);
  };

  if (loading) return (
    <ChromeInsetCard>
      <div style={{ textAlign: "center", padding: "32px" }}>
        <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 12px", color: "var(--tc-red)" }} />
        <div style={{ fontSize: "13px", color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "Chargement des scenarios..." : "Loading scenarios..."}
        </div>
      </div>
    </ChromeInsetCard>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: "16px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>
          {locale === "fr" ? "Simulation d'attaques" : "Attack Simulation"}
        </h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
          {locale === "fr"
            ? "Scenarios realistes pour tester le pipeline complet. Les donnees sont isolees et supprimees automatiquement."
            : "Realistic scenarios to test the full pipeline. Data is isolated and automatically cleaned up."}
        </p>
      </div>

      {/* Isolation banner */}
      <div style={{
        display: "flex", alignItems: "center", gap: "10px", padding: "10px 14px", marginBottom: "16px",
        borderRadius: "var(--tc-radius-card)", background: "rgba(48,128,208,0.06)", border: "1px solid rgba(48,128,208,0.15)",
      }}>
        <Info size={16} color="#3080d0" style={{ flexShrink: 0 }} />
        <div style={{ flex: 1, fontSize: "11px", color: "#3080d0", lineHeight: "1.5" }}>
          {locale === "fr"
            ? "Les donnees de simulation sont taguees [DEMO] et isolees de la production. Elles sont supprimees automatiquement apres 1 heure. Le ML ne sera pas contamine. Les rapports NIS2/ISO excluent les donnees demo."
            : "Simulation data is tagged [DEMO] and isolated from production. It is automatically deleted after 1 hour. ML baseline will not be affected. NIS2/ISO reports exclude demo data."}
        </div>
      </div>

      {/* Demo data status + cleanup */}
      {demoStatus.total > 0 && (
        <ChromeInsetCard style={{ marginBottom: "16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>
                {locale === "fr" ? "Donnees de simulation presentes" : "Simulation data present"}
              </div>
              <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
                {demoStatus.demo_findings} findings + {demoStatus.demo_alerts} {locale === "fr" ? "alertes" : "alerts"}
              </div>
            </div>
            <ChromeButton onClick={cleanupDemo} disabled={cleaning} variant="glass">
              {cleaning ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
              {locale === "fr" ? "Nettoyer maintenant" : "Clean up now"}
            </ChromeButton>
          </div>
        </ChromeInsetCard>
      )}

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
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", textTransform: "uppercase" }}>Score</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--tc-text)", marginBottom: "4px" }}>
                Situation : <span style={{
                  color: situation.notification_level === "silence" ? "#30a050" : situation.notification_level === "digest" ? "#3080d0" : "#d03020",
                }}>{situation.notification_level || "silence"}</span>
              </div>
              <div style={{ fontSize: "12px", color: "var(--tc-text-muted)" }}>
                {situation.open_findings || 0} findings — {situation.active_alerts || 0} {locale === "fr" ? "alertes" : "alerts"}
              </div>
            </div>
            <ChromeButton onClick={() => { refreshSituation(); refreshDemoStatus(); }} variant="glass">
              <RefreshCw size={14} /> {locale === "fr" ? "Rafraichir" : "Refresh"}
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
            <ChromeInsetCard key={s.id} style={{ borderRadius: "var(--tc-radius-card)" }}>
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
                      fontSize: "9px", color: "var(--tc-text-muted)", display: "flex", alignItems: "center", gap: "3px",
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
                      <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>{result.time}</span>
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
                  {isRunning ? (locale === "fr" ? "En cours..." : "Running...") : (locale === "fr" ? "Lancer" : "Run")}
                </ChromeButton>
              </div>
            </ChromeInsetCard>
          );
        })}
      </div>

      {/* Info */}
      <ChromeInsetCard style={{ marginTop: "20px" }}>
        <div style={{ fontSize: "12px", color: "var(--tc-text-muted)", lineHeight: 1.7 }}>
          <strong style={{ color: "var(--tc-text)" }}>
            {locale === "fr" ? "Comment ca marche" : "How it works"}
          </strong>
          <br /><br />
          {locale === "fr" ? (
            <>
              Chaque scenario injecte des <strong style={{ color: "var(--tc-text)" }}>vrais logs</strong> dans PostgreSQL,
              cree des <strong style={{ color: "var(--tc-text)" }}>findings</strong> et des <strong style={{ color: "var(--tc-text)" }}>alertes Sigma</strong>.
              <br /><br />
              {"L'Intelligence Engine traite ces donnees exactement comme en production : extraction d'IoCs, enrichissement (EPSS, GreyNoise, IPinfo), calcul du score, notification operateur."}
              <br /><br />
              <strong style={{ color: "var(--tc-green)" }}>Toutes les donnees sont taguees [DEMO]</strong> et isolees de la production.
              Elles sont supprimees automatiquement apres 1 heure. Le baseline ML n'est pas affecte.
              Tous les IoCs utilises sont <strong style={{ color: "var(--tc-red)" }}>reels</strong> (IPs Tor, CVEs exploitees).
            </>
          ) : (
            <>
              Each scenario injects <strong style={{ color: "var(--tc-text)" }}>real logs</strong> into PostgreSQL,
              creates <strong style={{ color: "var(--tc-text)" }}>findings</strong> and <strong style={{ color: "var(--tc-text)" }}>Sigma alerts</strong>.
              <br /><br />
              The Intelligence Engine processes this data exactly like production: IoC extraction, enrichment (EPSS, GreyNoise, IPinfo), scoring, operator notification.
              <br /><br />
              <strong style={{ color: "var(--tc-green)" }}>All data is tagged [DEMO]</strong> and isolated from production.
              Automatically deleted after 1 hour. ML baseline is not affected.
              All IoCs used are <strong style={{ color: "var(--tc-red)" }}>real</strong> (Tor IPs, exploited CVEs).
            </>
          )}
        </div>
      </ChromeInsetCard>
    </div>
  );
}

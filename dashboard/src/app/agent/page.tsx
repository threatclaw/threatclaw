"use client";

import React, { useState, useEffect, useCallback } from "react";
import { ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { NeuCard as ChromeInsetCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { Shield, AlertOctagon, Play, Loader2, Eye, Bell, ShieldCheck, Zap, CheckCircle2, Clock } from "lucide-react";
import {
  fetchAgentMode, setAgentMode, fetchKillSwitch, triggerKillSwitch,
  fetchSoulInfo, triggerReactCycle, fetchAuditEntries,
  type AgentModeResponse, type KillSwitchStatus, type SoulInfo,
  type ReactCycleResponse, type AuditRawEntry,
} from "@/lib/tc-agent-api";

const MODE_ICONS: Record<string, React.ElementType> = {
  analyst: Eye, investigator: Bell, responder: ShieldCheck, autonomous_low: Zap,
};

export default function AgentPage() {
  const [mode, setMode] = useState<AgentModeResponse | null>(null);
  const [killSwitch, setKillSwitchState] = useState<KillSwitchStatus | null>(null);
  const [soul, setSoul] = useState<SoulInfo | null>(null);
  const [lastAnalysis, setLastAnalysis] = useState<ReactCycleResponse | null>(null);
  const [audit, setAudit] = useState<AuditRawEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [cycleRunning, setCycleRunning] = useState(false);
  const [killConfirm, setKillConfirm] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [m, ks, s, a] = await Promise.all([
        fetchAgentMode(), fetchKillSwitch(), fetchSoulInfo(), fetchAuditEntries(),
      ]);
      setMode(m); setKillSwitchState(ks); setSoul(s); setAudit(a.entries);
    } catch { /* not ready */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); const i = setInterval(refresh, 10000); return () => clearInterval(i); }, [refresh]);

  const handleRunCycle = async () => {
    setCycleRunning(true);
    try { const r = await triggerReactCycle(); setLastAnalysis(r); await refresh(); }
    catch { /* */ } finally { setCycleRunning(false); }
  };

  if (loading) return (
    <ChromeInsetCard>
      <div style={{ textAlign: "center", padding: "40px" }}>
        <Loader2 size={20} color="#903020" className="animate-spin" style={{ margin: "0 auto" }} />
        <ChromeEmbossedText as="div" style={{ fontSize: "10px", opacity: 0.5, marginTop: "8px" }}>Connexion...</ChromeEmbossedText>
      </div>
    </ChromeInsetCard>
  );

  return (
    <div>
      {/* Soul + Kill Switch row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
        <ChromeInsetCard>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Shield size={16} color={soul?.status === "verified" ? "#5a7a4a" : "#903020"} />
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 700 }}>{soul?.name || "Agent Soul"}</ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.45 }}>
                {soul?.status === "verified" ? `v${soul.version} · ${soul.rules_count} règles · OK` : "Erreur"}
              </ChromeEmbossedText>
            </div>
          </div>
        </ChromeInsetCard>

        <ChromeInsetCard>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <AlertOctagon size={16} color={killSwitch?.active ? "#5a7a4a" : "#903020"} />
              <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 700 }}>Kill Switch</ChromeEmbossedText>
            </div>
            {killConfirm ? (
              <div style={{ display: "flex", gap: "4px" }}>
                <ChromeButton onClick={async () => { await triggerKillSwitch("rssi"); setKillConfirm(false); await refresh(); }}>
                  <span style={{ fontSize: "8px", color: "#903020" }}>CONFIRMER</span>
                </ChromeButton>
                <ChromeButton onClick={() => setKillConfirm(false)}>
                  <span style={{ fontSize: "8px" }}>Annuler</span>
                </ChromeButton>
              </div>
            ) : (
              <ChromeButton onClick={() => setKillConfirm(true)}>
                <span style={{ fontSize: "8px" }}>ARRÊT URGENCE</span>
              </ChromeButton>
            )}
          </div>
        </ChromeInsetCard>
      </div>

      {/* Mode selector */}
      <ChromeInsetCard className="mb-3">
        <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: "8px" }}>
          Mode agent
        </ChromeEmbossedText>
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
          {mode?.available_modes.map(m => {
            const Icon = MODE_ICONS[m.id] || Shield;
            const isActive = mode.current_mode === m.id;
            return (
              <ChromeButton key={m.id} onClick={() => !isActive && setAgentMode(m.id).then(refresh)}>
                <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "9px", opacity: isActive ? 1 : 0.5 }}>
                  <Icon size={11} />
                  {m.name}
                  {isActive && <CheckCircle2 size={10} color="#5a7a4a" />}
                </span>
              </ChromeButton>
            );
          })}
        </div>
      </ChromeInsetCard>

      {/* React cycle trigger */}
      <ChromeInsetCard className="mb-3">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase" }}>
            Lancer une analyse
          </ChromeEmbossedText>
          <ChromeButton onClick={handleRunCycle} disabled={cycleRunning}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "9px" }}>
              {cycleRunning ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
              {cycleRunning ? "Analyse..." : "Lancer"}
            </span>
          </ChromeButton>
        </div>

        {lastAnalysis?.analysis && (
          <div style={{ marginTop: "12px", borderTop: "1px solid rgba(0,0,0,0.06)", paddingTop: "10px" }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "10px", lineHeight: 1.5, marginBottom: "6px" }}>
              {lastAnalysis.analysis.analysis}
            </ChromeEmbossedText>
            <div style={{ display: "flex", gap: "8px", fontSize: "8px" }}>
              <ChromeEmbossedText as="span" style={{ fontWeight: 700, color: "#903020" }}>{lastAnalysis.analysis.severity}</ChromeEmbossedText>
              <ChromeEmbossedText as="span" style={{ opacity: 0.4 }}>L{lastAnalysis.escalation_level}</ChromeEmbossedText>
              <ChromeEmbossedText as="span" style={{ opacity: 0.4 }}>{Math.round(lastAnalysis.analysis.confidence * 100)}% confiance</ChromeEmbossedText>
              <ChromeEmbossedText as="span" style={{ opacity: 0.4 }}>{lastAnalysis.analysis.correlations.length} corrélations</ChromeEmbossedText>
            </div>
          </div>
        )}
      </ChromeInsetCard>

      {/* Audit log */}
      <ChromeInsetCard>
        <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: "8px" }}>
          Journal d{"'"}audit ({audit.length})
        </ChromeEmbossedText>
        {audit.length === 0 ? (
          <div style={{ textAlign: "center", padding: "12px" }}>
            <Clock size={14} color="#907060" style={{ margin: "0 auto 4px" }} />
            <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.4 }}>
              Le journal se remplira après un analyse manuelle
            </ChromeEmbossedText>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {audit.slice(0, 15).map((e, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px 0", borderBottom: "1px solid rgba(0,0,0,0.04)" }}>
                <div style={{ width: "5px", height: "5px", borderRadius: "50%", background: e.success ? "#5a7a4a" : "#903020", flexShrink: 0 }} />
                <ChromeEmbossedText as="span" style={{ fontSize: "9px", fontWeight: 600, flex: 1 }}>{e.event_type}</ChromeEmbossedText>
                <ChromeEmbossedText as="span" style={{ fontSize: "8px", opacity: 0.35 }}>
                  {e.timestamp ? new Date(e.timestamp).toLocaleString("fr-FR", { hour: "2-digit", minute: "2-digit" }) : ""}
                </ChromeEmbossedText>
              </div>
            ))}
          </div>
        )}
      </ChromeInsetCard>
    </div>
  );
}

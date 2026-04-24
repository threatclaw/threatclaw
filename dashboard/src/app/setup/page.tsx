"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import SetupWizard from "@/components/setup/SetupWizard";
import EmbossedButton from "@/components/chrome/EmbossedButton";
import ConfigPage from "@/components/setup/ConfigPage";
import { Settings, Play, Key, Monitor, Copy, RefreshCw } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

// Lazy load the sub-pages to avoid circular imports
const TestsContent = dynamic(() => import("../test/page"), { ssr: false });
const LicenseContent = dynamic(() => Promise.resolve({ default: LicensePage }), { ssr: false });

// Skills and Assets are first-class top-nav entries now (see
// SocTopBar + sections.ts). What remains in Config is the actual
// configuration surface: general settings, agent install, simulation
// (tests), and the about/license screen.
const TABS = [
  { key: "config", i18n: "general", icon: Settings },
  { key: "agent", i18n: "agent", icon: Monitor },
  { key: "tests", i18n: "tests", icon: Play },
  { key: "about", i18n: "about", icon: Key },
] as const;

// ── Agent Endpoint Tab ──
function AgentPage() {
  const locale = useLocale();
  const [osTab, setOsTab] = useState<"linux" | "windows">("linux");
  const [token, setToken] = useState<string | null>(null);
  const [tokenExists, setTokenExists] = useState(false);
  const [agents, setAgents] = useState<any[]>([]);
  const [serverUrl, setServerUrl] = useState("");
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Load token + agents
    // Pre-fill URL from current browser location (editable by RSSI)
    if (typeof window !== "undefined") {
      setServerUrl(`https://${window.location.hostname}`);
    }
    Promise.all([
      fetch("/api/tc/webhook/token/osquery").then(r => r.json()).catch(() => ({})),
      fetch("/api/tc/endpoint-agents").then(r => r.json()).catch(() => ({ agents: [] })),
    ]).then(([tokenData, agentsData]) => {
      if (tokenData.exists) {
        setToken(tokenData.token);
        setTokenExists(true);
      }
      setAgents(agentsData.agents || []);
      setLoading(false);
    });
  }, []);

  const generateToken = async () => {
    const res = await fetch("/api/tc/webhook/token/osquery", { method: "POST" });
    const data = await res.json();
    if (data.token) {
      setToken(data.token);
      setTokenExists(true);
    }
  };

  const copyCmd = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const linuxCmd = token
    ? `curl -fsSL https://get.threatclaw.io/agent | sudo bash -s -- \\\n  --url ${serverUrl} --token ${token}`
    : `curl -fsSL https://get.threatclaw.io/agent | sudo bash -s -- \\\n  --url ${serverUrl} --token VOTRE_TOKEN`;

  const windowsCmd = token
    ? `$env:TC_URL='${serverUrl}'; $env:TC_TOKEN='${token}'; irm get.threatclaw.io/agent/windows | iex`
    : `$env:TC_URL='${serverUrl}'; $env:TC_TOKEN='VOTRE_TOKEN'; irm get.threatclaw.io/agent/windows | iex`;

  if (loading) return <div style={{ padding: "20px", color: "var(--tc-text-muted)", fontSize: "12px" }}>Chargement...</div>;

  return (
    <div style={{ padding: "0 24px" }}>
      {/* Header */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "4px" }}>
          {locale === "fr" ? "ThreatClaw Agent" : "ThreatClaw Agent"}
        </div>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", lineHeight: "1.5" }}>
          {locale === "fr"
            ? "Deployez l'agent sur vos endpoints (serveurs, postes) pour collecter la telemetrie : inventaire logiciel, connexions reseau, ports ouverts, utilisateurs, event logs. Les donnees sont envoyees a ThreatClaw toutes les 5 minutes pour analyse et correlation."
            : "Deploy the agent on your endpoints (servers, workstations) to collect telemetry: software inventory, network connections, open ports, users, event logs. Data is sent to ThreatClaw every 5 minutes for analysis and correlation."}
        </div>
      </div>

      {/* Connection section */}
      <div className="tc-card" style={{ padding: "16px", marginBottom: "16px" }}>
        <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "12px" }}>
          {locale === "fr" ? "Connexion" : "Connection"}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {/* Server URL — editable */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", minWidth: "100px" }}>
              {locale === "fr" ? "URL du serveur" : "Server URL"}
            </span>
            <input
              type="text"
              value={serverUrl}
              onChange={e => setServerUrl(e.target.value)}
              placeholder="https://IP_DE_VOTRE_SERVEUR"
              style={{ fontSize: "11px", color: "var(--tc-blue)", background: "var(--tc-neu-inner)", padding: "6px 10px", borderRadius: "var(--tc-radius-sm)", flex: 1, border: "1px solid var(--tc-border)", fontFamily: "monospace", outline: "none" }}
            />
            <span style={{ fontSize: "9px", color: "var(--tc-text-faint)", whiteSpace: "nowrap" }}>
              {locale === "fr" ? "IP accessible par vos endpoints" : "IP reachable by your endpoints"}
            </span>
          </div>

          {/* Token */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", minWidth: "100px" }}>
              {locale === "fr" ? "Token webhook" : "Webhook token"}
            </span>
            {tokenExists && token ? (
              <>
                <code style={{ fontSize: "10px", color: "var(--tc-green)", background: "var(--tc-neu-inner)", padding: "6px 10px", borderRadius: "var(--tc-radius-sm)", flex: 1, fontFamily: "monospace", letterSpacing: "0.02em" }}>
                  {token.substring(0, 8)}{"••••••••••••••••"}
                </code>
                <button onClick={() => copyCmd(token)} className="tc-btn-embossed" style={{ fontSize: "9px", padding: "5px 8px", display: "flex", alignItems: "center", gap: "4px" }}>
                  <Copy size={10} /> {locale === "fr" ? "Copier" : "Copy"}
                </button>
                <button onClick={generateToken} className="tc-btn-embossed" style={{ fontSize: "9px", padding: "5px 8px", display: "flex", alignItems: "center", gap: "4px" }}>
                  <RefreshCw size={10} /> {locale === "fr" ? "Regenerer" : "Regenerate"}
                </button>
              </>
            ) : (
              <button onClick={generateToken} className="tc-btn-embossed" style={{ fontSize: "11px", padding: "7px 14px", background: "var(--tc-red)", color: "#fff", border: "none" }}>
                {locale === "fr" ? "Generer le token" : "Generate token"}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Installation section */}
      <div className="tc-card" style={{ padding: "16px", marginBottom: "16px" }}>
        <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "12px" }}>
          {locale === "fr" ? "Installation" : "Installation"}
        </div>

        {/* OS tabs */}
        <div style={{ display: "flex", gap: "0", marginBottom: "12px" }}>
          {(["linux", "windows"] as const).map(os => (
            <button key={os} onClick={() => setOsTab(os)} style={{
              padding: "6px 16px", fontSize: "11px", fontWeight: 600, border: "1px solid var(--tc-border)",
              borderBottom: osTab === os ? "2px solid var(--tc-red)" : "1px solid var(--tc-border)",
              background: osTab === os ? "var(--tc-surface-alt)" : "transparent",
              color: osTab === os ? "var(--tc-text)" : "var(--tc-text-muted)",
              cursor: "pointer", borderRadius: os === "linux" ? "6px 0 0 0" : "0 6px 0 0",
            }}>
              {os === "linux" ? "Linux / macOS" : "Windows"}
            </button>
          ))}
        </div>

        {/* Command display */}
        <div style={{ position: "relative" }}>
          <pre style={{
            background: "var(--tc-neu-inner)", padding: "14px 16px", borderRadius: "var(--tc-radius-sm)",
            fontSize: "11px", fontFamily: "monospace", color: osTab === "linux" ? "var(--tc-green)" : "var(--tc-blue)",
            lineHeight: "1.6", overflowX: "auto", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all",
          }}>
            {osTab === "linux" ? linuxCmd : windowsCmd}
          </pre>
          <button
            onClick={() => copyCmd(osTab === "linux" ? linuxCmd.replace(/\\\n\s*/g, "") : windowsCmd)}
            className="tc-btn-embossed"
            style={{ position: "absolute", top: "8px", right: "8px", fontSize: "9px", padding: "4px 8px", display: "flex", alignItems: "center", gap: "4px" }}
          >
            <Copy size={10} /> {copied ? (locale === "fr" ? "Copie !" : "Copied!") : (locale === "fr" ? "Copier" : "Copy")}
          </button>
        </div>

        {!tokenExists && (
          <div style={{ marginTop: "10px", fontSize: "10px", color: "var(--tc-text-faint)", fontStyle: "italic" }}>
            {locale === "fr"
              ? "Generez d'abord un token ci-dessus pour obtenir la commande complete."
              : "Generate a token above first to get the complete command."}
          </div>
        )}

        <div style={{ marginTop: "12px", fontSize: "10px", color: "var(--tc-text-muted)", lineHeight: "1.6" }}>
          {osTab === "linux" ? (
            locale === "fr"
              ? "Necessite root (sudo). Installe osquery (lecture seule, aucune action sur le systeme), configure 13 queries de collecte (logiciels, ports, users, SSH keys, crontab, Docker), cree un timer systemd (sync toutes les 5 min). Compatible Debian, Ubuntu, RHEL, CentOS, Fedora, macOS."
              : "Requires root (sudo). Installs osquery (read-only, no actions on the system), configures 13 collection queries (software, ports, users, SSH keys, crontab, Docker), creates a systemd timer (sync every 5 min). Supports Debian, Ubuntu, RHEL, CentOS, Fedora, macOS."
          ) : (
            locale === "fr"
              ? "Necessite PowerShell en administrateur. Installe osquery (MSI silencieux, lecture seule). Collecte : logiciels installes, connexions reseau, ports ouverts, utilisateurs, taches planifiees, services, patches KB, Windows Event Log (logon/privilege), PowerShell script block logging. Aucune action sur le systeme. Sync toutes les 5 min via Scheduled Task."
              : "Requires PowerShell as administrator. Installs osquery (silent MSI, read-only). Collects: installed software, network connections, open ports, users, scheduled tasks, services, KB patches, Windows Event Log (logon/privilege), PowerShell script block logging. No actions on the system. Syncs every 5 min via Scheduled Task."
          )}
        </div>
      </div>

      {/* Registered agents */}
      <div className="tc-card" style={{ padding: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
          <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            {locale === "fr" ? `Agents enregistres (${agents.length})` : `Registered agents (${agents.length})`}
          </div>
        </div>

        {agents.length === 0 ? (
          <div style={{ fontSize: "11px", color: "var(--tc-text-faint)", fontStyle: "italic", padding: "16px 0", textAlign: "center" }}>
            {locale === "fr"
              ? "Aucun agent enregistre. Installez l'agent sur un endpoint pour le voir ici."
              : "No registered agents. Install the agent on an endpoint to see it here."}
          </div>
        ) : (
          <table style={{ width: "100%", fontSize: "11px", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--tc-border)" }}>
                <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--tc-text-muted)", fontWeight: 600 }}>Agent ID</th>
                <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--tc-text-muted)", fontWeight: 600 }}>Hostname</th>
                <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--tc-text-muted)", fontWeight: 600 }}>{locale === "fr" ? "Dernier sync" : "Last sync"}</th>
                <th style={{ textAlign: "center", padding: "6px 8px", color: "var(--tc-text-muted)", fontWeight: 600 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent: any, i: number) => {
                const lastSeen = agent.last_seen ? new Date(agent.last_seen) : null;
                const now = new Date();
                const diffMin = lastSeen ? Math.floor((now.getTime() - lastSeen.getTime()) / 60000) : 999;
                const isOnline = diffMin < 10;
                return (
                  <tr key={i} style={{ borderBottom: "1px solid var(--tc-border)" }}>
                    <td style={{ padding: "8px", color: "var(--tc-text)", fontFamily: "monospace", fontSize: "10px" }}>
                      {agent.agent_id || `agent_${i}`}
                    </td>
                    <td style={{ padding: "8px", color: "var(--tc-text)" }}>{agent.hostname || "—"}</td>
                    <td style={{ padding: "8px", color: "var(--tc-text-muted)" }}>
                      {lastSeen
                        ? (diffMin < 1 ? (locale === "fr" ? "< 1 min" : "< 1 min") : `${diffMin} min`)
                        : "—"}
                    </td>
                    <td style={{ padding: "8px", textAlign: "center" }}>
                      <span style={{
                        display: "inline-block", width: "8px", height: "8px", borderRadius: "50%",
                        background: isOnline ? "#30a050" : "var(--tc-text-faint)",
                      }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── About + Account Tab Component ──
function LicensePage() {
  const locale = useLocale();
  const [info, setInfo] = React.useState<any>(null);
  const [user, setUser] = React.useState<any>(null);
  const [currentPwd, setCurrentPwd] = React.useState("");
  const [newPwd, setNewPwd] = React.useState("");
  const [pwdMsg, setPwdMsg] = React.useState("");
  const [pwdOk, setPwdOk] = React.useState(false);
  const [changingPwd, setChangingPwd] = React.useState(false);

  React.useEffect(() => {
    fetch("/api/tc/license").then(r => r.json()).then(setInfo).catch(() => {});
    fetch("/api/auth/me").then(r => r.json()).then(d => { if (d.authenticated) setUser(d.user); }).catch(() => {});
  }, []);

  const changePassword = async () => {
    setChangingPwd(true); setPwdMsg(""); setPwdOk(false);
    try {
      const res = await fetch("/api/auth/password", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: currentPwd, newPassword: newPwd }),
      });
      const data = await res.json();
      if (data.ok) {
        setPwdOk(true); setPwdMsg(tr("passwordChanged", locale));
        setCurrentPwd(""); setNewPwd("");
      } else {
        setPwdMsg(data.error || "Erreur");
      }
    } catch { setPwdMsg("Erreur réseau"); }
    setChangingPwd(false);
  };

  return (
    <div style={{ padding: "20px 24px" }}>
      <h2 style={{ fontSize: "18px", fontWeight: 800, color: "var(--tc-text)", margin: "0 0 16px" }}>ThreatClaw</h2>

      {/* Instance info */}
      <div className="tc-card" style={{ padding: "20px", marginBottom: "16px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>{tr("instance", locale)}</span>
            <span style={{ fontSize: "13px", fontWeight: 700, fontFamily: "monospace", color: "var(--tc-text)" }}>
              {info?.instance_id || "..."}
            </span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>{tr("assets", locale)}</span>
            <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>
              {info?.asset_count || 0} <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontWeight: 400 }}>{tr("noLimit", locale)}</span>
            </span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>{locale === "fr" ? "Licence" : "License"}</span>
            <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-green)" }}>
              {tr("freeUnlimited", locale)}
            </span>
          </div>
        </div>
      </div>

      {/* Account */}
      {user && (
        <div className="tc-card" style={{ padding: "20px", marginBottom: "16px" }}>
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", margin: "0 0 12px" }}>{tr("myAccount", locale)}</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
              <span style={{ color: "var(--tc-text-muted)" }}>{tr("email", locale)}</span>
              <span style={{ color: "var(--tc-text)", fontWeight: 600 }}>{user.email}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
              <span style={{ color: "var(--tc-text-muted)" }}>{tr("role", locale)}</span>
              <span style={{ color: "var(--tc-text)", fontWeight: 600, textTransform: "capitalize" }}>{user.role}</span>
            </div>
          </div>
          <div style={{ borderTop: "1px solid var(--tc-border)", paddingTop: "12px" }}>
            <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "10px" }}>{tr("changePassword", locale)}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <input type="password" value={currentPwd} onChange={e => setCurrentPwd(e.target.value)} placeholder={tr("currentPassword", locale)}
                style={{ padding: "8px 10px", fontSize: "12px", borderRadius: "var(--tc-radius-input)", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none" }} />
              <input type="password" value={newPwd} onChange={e => setNewPwd(e.target.value)} placeholder={tr("newPassword", locale)}
                style={{ padding: "8px 10px", fontSize: "12px", borderRadius: "var(--tc-radius-input)", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none" }} />
              <button onClick={changePassword} disabled={changingPwd || !currentPwd || newPwd.length < 8}
                className="tc-btn-embossed" style={{ fontSize: "11px", padding: "8px 14px", alignSelf: "flex-start" }}>
                {changingPwd ? "..." : tr("modify", locale)}
              </button>
              {pwdMsg && (
                <div style={{ fontSize: "11px", color: pwdOk ? "var(--tc-green)" : "var(--tc-red)", marginTop: "4px" }}>
                  {pwdMsg}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="tc-card" style={{ padding: "20px" }}>
        <p style={{ fontSize: "12px", color: "var(--tc-text-muted)", lineHeight: "1.6", margin: 0 }}>
          ThreatClaw est un agent cybersécurité autonome pour PME.
          <br />Développé par <a href="https://cyberconsulting.fr" target="_blank" rel="noopener noreferrer" style={{ color: "var(--tc-red)", textDecoration: "none" }}>CyberConsulting.fr</a>
          <br />Licence AGPL v3 — <a href="https://threatclaw.io" target="_blank" rel="noopener noreferrer" style={{ color: "var(--tc-red)", textDecoration: "none" }}>threatclaw.io</a>
        </p>
      </div>
    </div>
  );
}

type TabKey = typeof TABS[number]["key"];

export default function SetupPage() {
  const locale = useLocale();
  const [onboarded, setOnboarded] = useState<boolean | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("config");

  useEffect(() => {
    setOnboarded(localStorage.getItem("threatclaw_onboarded") === "true");
    // Respond to both legacy #hash and the new ?tab= query string used by
    // PageShell's left sub-menu. Query string wins when both are present.
    const params = new URLSearchParams(window.location.search);
    const tabQs = params.get("tab");
    if (tabQs && TABS.some(t => t.key === tabQs)) {
      setActiveTab(tabQs as TabKey);
      return;
    }
    const hash = window.location.hash.replace("#", "");
    if (hash && TABS.some(t => t.key === hash)) {
      setActiveTab(hash as TabKey);
    }
  }, []);

  if (onboarded === null) return null;

  if (!onboarded) {
    return (
      <div style={{ margin: "-0 -20px" }}>
        <SetupWizard />
      </div>
    );
  }

  return (
    <div>
      {/* Tab bar — sliding indicator */}
      <div style={{
        position: "relative", display: "flex", padding: "3px",
        margin: "0 24px 8px", borderRadius: "11px",
        background: "var(--tc-input)",
      }}>
        {/* Sliding indicator */}
        <div style={{
          position: "absolute", top: "3px", height: "calc(100% - 6px)",
          width: `calc(${100 / TABS.length}% - 2px)`,
          left: `calc(${(TABS.findIndex(t => t.key === activeTab)) * (100 / TABS.length)}% + 1px)`,
          background: "var(--tc-surface-alt)",
          borderRadius: "8px",
          border: "0.5px solid var(--tc-border)",
          boxShadow: "0 3px 8px rgba(0,0,0,0.12), 0 3px 1px rgba(0,0,0,0.04)",
          transition: "left 0.25s ease-out",
          zIndex: 0,
        }} />
        {TABS.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => {
                setActiveTab(tab.key);
                // Update ?tab= so PageShell's left sub-menu stays in sync
                // and the URL is shareable. Kept #hash too as a fallback.
                const qs = new URLSearchParams(window.location.search);
                qs.set("tab", tab.key);
                window.history.replaceState(
                  null,
                  "",
                  `${window.location.pathname}?${qs.toString()}`,
                );
              }}
              style={{
                flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
                gap: "6px", padding: "8px 0", fontSize: "11px", fontWeight: 600,
                color: isActive ? "var(--tc-text)" : "var(--tc-text-muted)",
                background: "transparent", border: "none",
                cursor: "pointer", transition: "color 200ms, opacity 200ms",
                position: "relative", zIndex: 1,
                opacity: isActive ? 1 : 0.5,
              }}
            >
              <Icon size={13} />
              {tr(tab.i18n, locale)}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      {activeTab === "config" && (
        <ConfigPage onResetWizard={() => {
          localStorage.removeItem("threatclaw_onboarded");
          setOnboarded(false);
        }} />
      )}
      {activeTab === "agent" && <AgentPage />}
      {activeTab === "tests" && <TestsContent />}
      {activeTab === "about" && <LicenseContent />}
    </div>
  );
}

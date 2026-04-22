"use client";

import React, { useState, useEffect, useCallback } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";
import {
  Radio, Shield, Server, Wifi, Eye, Globe, FileSearch, Bug, Puzzle,
  CheckCircle2, AlertTriangle, XCircle, Clock, Copy, Check,
  ChevronDown, ChevronRight, RefreshCw, Plus, Zap, Lock,
} from "lucide-react";

// ── Source definitions with setup guides ──

interface SourceDef {
  id: string;
  icon: React.ReactNode;
  color: string;
  description: { fr: string; en: string };
  guides: { title: string; titleEn: string; steps: string[] }[];
}

const SOURCE_DEFS: Record<string, SourceDef> = {
  syslog: {
    id: "syslog",
    icon: <Radio size={20} />,
    color: "#6090d0",
    description: {
      fr: "Recevez les logs de vos serveurs, firewalls et equipements reseau via syslog UDP/TCP sur le port 514. Aucune configuration cote ThreatClaw necessaire.",
      en: "Receive logs from your servers, firewalls and network devices via syslog UDP/TCP on port 514. No ThreatClaw-side configuration needed.",
    },
    guides: [
      {
        title: "Linux (rsyslog)", titleEn: "Linux (rsyslog)",
        steps: [
          "echo '*.* @@ADDR:514' | sudo tee /etc/rsyslog.d/threatclaw.conf",
          "sudo systemctl restart rsyslog",
        ],
      },
      {
        title: "Firewall (pfSense / OPNsense)", titleEn: "Firewall (pfSense / OPNsense)",
        steps: [
          "Status > System Logs > Settings",
          "Enable Remote Logging, Remote log servers: ADDR:514",
          "Save + Apply",
        ],
      },
      {
        title: "Windows (NXLog)", titleEn: "Windows (NXLog)",
        steps: [
          "Install NXLog CE: https://nxlog.co/downloads/nxlog-ce",
          "Edit C:\\Program Files\\nxlog\\conf\\nxlog.conf:",
          '<Output out>\n  Module om_tcp\n  Host ADDR\n  Port 514\n</Output>',
          "Restart NXLog service",
        ],
      },
    ],
  },
  wazuh: {
    id: "wazuh",
    icon: <Shield size={20} />,
    color: "#3080d0",
    description: {
      fr: "Connectez votre Wazuh Manager pour importer les alertes SIEM, la detection d'intrusion, le file integrity monitoring et les vulnerabilites.",
      en: "Connect your Wazuh Manager to import SIEM alerts, intrusion detection, file integrity monitoring and vulnerabilities.",
    },
    guides: [
      {
        title: "Configuration", titleEn: "Setup",
        steps: [
          "Dashboard > Skills > Wazuh > Configurer",
          "URL: https://wazuh-manager:55000",
          "Username / Password: wazuh API credentials",
          "ThreatClaw synchronise automatiquement toutes les 2-5 minutes",
        ],
      },
    ],
  },
  osquery: {
    id: "osquery",
    icon: <Eye size={20} />,
    color: "#30a060",
    description: {
      fr: "Installez l'agent ThreatClaw (base osquery) sur vos machines pour la visibilite endpoint : processus, logiciels, connexions reseau, evenements fichiers.",
      en: "Install the ThreatClaw agent (osquery-based) on your machines for endpoint visibility: processes, software, network connections, file events.",
    },
    guides: [
      {
        title: "Linux / macOS", titleEn: "Linux / macOS",
        steps: [
          "curl -fsSL https://get.threatclaw.io/agent | sudo bash -s -- --url https://ADDR --token TOKEN",
          "L'agent se configure automatiquement (systemd timer, 5 min sync)",
        ],
      },
      {
        title: "Windows (MSI)", titleEn: "Windows (MSI)",
        steps: [
          "Telechargez osquery MSI: https://osquery.io/downloads",
          "Installez + configurez le webhook vers https://ADDR/api/tc/webhook/ingest/osquery",
          "Utilisez le token genere ci-dessous dans le header X-Webhook-Token",
        ],
      },
    ],
  },
  zeek: {
    id: "zeek",
    icon: <Wifi size={20} />,
    color: "#d07020",
    description: {
      fr: "Connectez Zeek pour l'analyse passive du trafic reseau. Active 7 modules NDR : fingerprinting TLS, detection C2, DNS tunneling, ransomware SMB.",
      en: "Connect Zeek for passive network traffic analysis. Activates 7 NDR modules: TLS fingerprinting, C2 detection, DNS tunneling, SMB ransomware.",
    },
    guides: [
      {
        title: "Installation Zeek + Fluent-Bit", titleEn: "Zeek + Fluent-Bit Setup",
        steps: [
          "Installez Zeek sur une machine avec acces au port SPAN/mirror du switch",
          "Copiez le local.zeek de reference depuis le repo ThreatClaw: docker/zeek/local.zeek",
          "Installez les packages: zkg install zeek/mitre-attack/bzar salesforce/hassh foxio/ja4 corelight/zeek-long-connections",
          "Configurez Fluent-Bit pour forwarder les logs JSON vers: POST https://ADDR/api/tc/webhook/ingest/zeek",
          "Reference config: docker/fluent-bit-zeek.conf dans le repo ThreatClaw",
        ],
      },
    ],
  },
  pihole: {
    id: "pihole",
    icon: <Globe size={20} />,
    color: "#d04040",
    description: {
      fr: "Connectez Pi-hole pour la visibilite DNS. Active la detection de DNS tunneling et le scoring DGA sur les requetes DNS de votre reseau.",
      en: "Connect Pi-hole for DNS visibility. Activates DNS tunneling detection and DGA scoring on your network's DNS queries.",
    },
    guides: [
      {
        title: "Configuration", titleEn: "Setup",
        steps: [
          "Dashboard > Skills > Pi-hole > Configurer",
          "URL: http://pihole-ip (port 80 par defaut)",
          "Mot de passe: votre mot de passe admin Pi-hole",
          "ThreatClaw interroge l'API Pi-hole automatiquement",
        ],
      },
    ],
  },
  suricata: {
    id: "suricata",
    icon: <Bug size={20} />,
    color: "#9060c0",
    description: {
      fr: "Connectez Suricata IDS pour la detection d'intrusion basee sur des signatures. Les alertes Suricata sont correlees avec les autres sources.",
      en: "Connect Suricata IDS for signature-based intrusion detection. Suricata alerts are correlated with other sources.",
    },
    guides: [
      {
        title: "Envoi des alertes", titleEn: "Alert Forwarding",
        steps: [
          "Configurez eve.json output dans suricata.yaml",
          "Utilisez Fluent-Bit pour forwarder les events vers:",
          "POST https://ADDR/api/tc/webhook/ingest/suricata",
          "Header: X-Webhook-Token: TOKEN",
        ],
      },
    ],
  },
  strelka: {
    id: "strelka",
    icon: <FileSearch size={20} />,
    color: "#c06060",
    description: {
      fr: "Connectez Strelka pour l'analyse approfondie de fichiers (79 scanners : ClamAV, YARA, capa). Scanne les fichiers extraits du reseau par Zeek.",
      en: "Connect Strelka for deep file analysis (79 scanners: ClamAV, YARA, capa). Scans files extracted from network traffic by Zeek.",
    },
    guides: [
      {
        title: "Installation Strelka", titleEn: "Strelka Setup",
        steps: [
          "docker pull target/strelka-backend:latest && docker pull target/strelka-frontend:latest",
          "Configurez le dossier d'extraction Zeek comme source pour Strelka",
          "Envoyez les resultats de scan vers: POST https://ADDR/api/tc/webhook/ingest/strelka",
          "Header: X-Webhook-Token: TOKEN",
          "Reference: skills/skill-strelka-scanner/skill.json",
        ],
      },
    ],
  },
};

// ── Status badge component ──

const STATUS_CONFIG = {
  connected: { color: "var(--tc-green)", bg: "transparent", border: "var(--tc-green)", icon: <CheckCircle2 size={12} /> },
  listening: { color: "var(--tc-text-sec)", bg: "transparent", border: "var(--tc-border)", icon: <Clock size={12} /> },
  configured: { color: "var(--tc-amber)", bg: "transparent", border: "var(--tc-amber)", icon: <AlertTriangle size={12} /> },
  not_configured: { color: "var(--tc-text-muted)", bg: "transparent", border: "var(--tc-border)", icon: <XCircle size={12} /> },
} as const;

const STATUS_LABELS: Record<string, { fr: string; en: string }> = {
  connected: { fr: "Connecte", en: "Connected" },
  listening: { fr: "En ecoute", en: "Listening" },
  configured: { fr: "Configure (pas de donnees)", en: "Configured (no data)" },
  not_configured: { fr: "Non configure", en: "Not configured" },
};

function StatusBadge({ status, locale }: { status: string; locale: string }) {
  const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.not_configured;
  const label = STATUS_LABELS[status] || STATUS_LABELS.not_configured;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "5px",
      padding: "3px 8px",
      fontSize: "9px", fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase",
      color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`,
    }}>
      {cfg.icon} {locale === "fr" ? label.fr : label.en}
    </span>
  );
}

// ── Copy button ──

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", padding: "2px", color: copied ? "var(--tc-green)" : "var(--tc-text-muted)" }}>
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  );
}

// ── Main page ──

interface SourceStatus {
  id: string;
  name: string;
  status: string;
  type: string;
  logs_24h: number;
  hosts: number;
  last_seen: string | null;
  sub_tags: string[];
  activates: string[];
  webhook_endpoint: string;
  webhook_token: string | null;
}

interface SourcesData {
  summary: { total_logs_24h: number; active_sources: number; total_sources: number; syslog_address: string };
  sources: SourceStatus[];
  agents: Array<{ hostname?: string; last_seen?: string }>;
}

export default function SourcesPage() {
  const locale = useLocale();
  const [data, setData] = useState<SourcesData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedSource, setExpandedSource] = useState<string | null>(null);
  const [generatingToken, setGeneratingToken] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/sources/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
      setError(null);
    } catch {
      setError(locale === "fr" ? "Impossible de charger le statut des sources" : "Failed to load source status");
    }
    setLoading(false);
  }, [locale]);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const generateToken = async (sourceId: string) => {
    setGeneratingToken(sourceId);
    try {
      const res = await fetch(`/api/tc/webhook/token/${sourceId}`, { method: "POST" });
      if (res.ok) { await load(); }
    } catch { /* ignore */ }
    setGeneratingToken(null);
  };

  if (loading && !data) {
    return (
      <div style={{ padding: "32px", textAlign: "center", color: "var(--tc-text-muted)" }}>
        {locale === "fr" ? "Chargement..." : "Loading..."}
      </div>
    );
  }

  const summary = data?.summary;
  const sources = data?.sources || [];
  const agents = data?.agents || [];
  const syslogAddr = summary?.syslog_address || "0.0.0.0:514";

  return (
    <PageShell
      title={locale === "fr" ? "Sources de données" : "Data Sources"}
      subtitle={
        locale === "fr"
          ? "Connectez vos sources pour activer les détections. Plus de sources = plus de visibilité."
          : "Connect your sources to activate detections. More sources = more visibility."
      }
    >
      {error && <ErrorBanner message={error} onRetry={load} />}

      {/* Summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "10px", marginBottom: "20px" }}>
        <NeuCard style={{ padding: "16px", textAlign: "center" }}>
          <div style={{ fontSize: "28px", fontWeight: 800, color: "var(--tc-text)" }}>{summary?.total_logs_24h?.toLocaleString() || 0}</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
            {locale === "fr" ? "Logs (24h)" : "Logs (24h)"}
          </div>
        </NeuCard>
        <NeuCard style={{ padding: "16px", textAlign: "center" }}>
          <div style={{ fontSize: "28px", fontWeight: 800, color: summary?.active_sources ? "var(--tc-green)" : "var(--tc-amber)" }}>
            {summary?.active_sources || 0}<span style={{ fontSize: "16px", color: "var(--tc-text-muted)" }}>/{summary?.total_sources || 7}</span>
          </div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
            {locale === "fr" ? "Sources actives" : "Active sources"}
          </div>
        </NeuCard>
        <NeuCard style={{ padding: "16px", textAlign: "center" }}>
          <div style={{ fontSize: "28px", fontWeight: 800, color: "var(--tc-text)" }}>{agents.length}</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
            {locale === "fr" ? "Agents deployes" : "Deployed agents"}
          </div>
        </NeuCard>
        <NeuCard style={{ padding: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
          <Radio size={16} color="var(--tc-text-sec)" />
          <div>
            <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", fontFamily: "monospace" }}>{syslogAddr}</div>
            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>Syslog UDP+TCP</div>
          </div>
          <CopyButton text={syslogAddr} />
        </NeuCard>
      </div>

      {/* Source cards */}
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {sources.map((source) => {
          const def = SOURCE_DEFS[source.id];
          if (!def) return null;

          const isExpanded = expandedSource === source.id;
          const hasData = source.logs_24h > 0;

          return (
            <NeuCard key={source.id} style={{ padding: "0", borderRadius: "var(--tc-radius-card)", overflow: "hidden" }}>
              {/* Header row */}
              <div
                onClick={() => setExpandedSource(isExpanded ? null : source.id)}
                style={{
                  display: "flex", alignItems: "center", gap: "14px", padding: "16px 18px",
                  cursor: "pointer", userSelect: "none",
                }}
              >
                {/* Icon — neutral square, red only when configured/active */}
                <div style={{
                  width: "38px", height: "38px", borderRadius: "2px",
                  background: "var(--tc-surface-alt)",
                  border: `1px solid ${hasData ? "var(--tc-red)" : "var(--tc-border)"}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color: hasData ? "var(--tc-red)" : "var(--tc-text-sec)", flexShrink: 0,
                }}>
                  {def.icon}
                </div>

                {/* Name + description */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)" }}>{source.name}</div>
                  <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "1px" }}>
                    {hasData ? (
                      <>
                        <span style={{ color: "var(--tc-green)", fontWeight: 600 }}>{source.logs_24h.toLocaleString()}</span> logs/24h
                        {source.hosts > 0 && <> &middot; {source.hosts} {locale === "fr" ? "hote(s)" : "host(s)"}</>}
                        {source.last_seen && <> &middot; {locale === "fr" ? "Dernier" : "Last"}: {new Date(source.last_seen).toLocaleTimeString()}</>}
                      </>
                    ) : (
                      locale === "fr" ? def.description.fr : def.description.en
                    )}
                  </div>
                </div>

                {/* Status badge */}
                <StatusBadge status={source.status} locale={locale} />

                {/* Expand arrow */}
                {isExpanded
                  ? <ChevronDown size={16} color="var(--tc-text-muted)" />
                  : <ChevronRight size={16} color="var(--tc-text-muted)" />
                }
              </div>

              {/* Expanded content */}
              {isExpanded && (
                <div style={{ borderTop: "1px solid var(--tc-border-light)", padding: "16px 18px" }}>
                  {/* What it activates */}
                  <div style={{ marginBottom: "16px" }}>
                    <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
                      <Zap size={12} style={{ verticalAlign: "middle", marginRight: "4px" }} />
                      {locale === "fr" ? "Detections activees" : "Activated detections"}
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                      {source.activates.map((a, i) => (
                        <span key={i} style={{
                          fontSize: "10px", fontWeight: 600, padding: "3px 8px",
                          borderRadius: "var(--tc-radius-sm)",
                          background: hasData ? "rgba(48,160,80,0.08)" : "var(--tc-input)",
                          color: hasData ? "var(--tc-green)" : "var(--tc-text-muted)",
                          border: `1px solid ${hasData ? "rgba(48,160,80,0.2)" : "var(--tc-border)"}`,
                        }}>
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Webhook info (for webhook-type sources) */}
                  {source.type === "webhook" && (
                    <div style={{ marginBottom: "16px" }}>
                      <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
                        <Lock size={12} style={{ verticalAlign: "middle", marginRight: "4px" }} />
                        Webhook
                      </div>
                      <div style={{
                        padding: "10px 12px", borderRadius: "var(--tc-radius-input)",
                        background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
                        fontSize: "12px", fontFamily: "monospace",
                      }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                          <span style={{ color: "var(--tc-text-muted)", fontSize: "10px", width: "70px" }}>Endpoint:</span>
                          <code style={{ color: "var(--tc-text)", flex: 1 }}>{source.webhook_endpoint}</code>
                          <CopyButton text={source.webhook_endpoint} />
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ color: "var(--tc-text-muted)", fontSize: "10px", width: "70px" }}>Token:</span>
                          {source.webhook_token ? (
                            <>
                              <code style={{ color: "var(--tc-text)", flex: 1 }}>{source.webhook_token}</code>
                              <CopyButton text={source.webhook_token} />
                            </>
                          ) : (
                            <ChromeButton variant="glass" onClick={() => generateToken(source.id)}
                              style={{ fontSize: "10px", padding: "4px 10px" }}>
                              {generatingToken === source.id ? "..." : (
                                <><Plus size={11} /> {locale === "fr" ? "Generer un token" : "Generate token"}</>
                              )}
                            </ChromeButton>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Connector info (for connector-type sources) */}
                  {source.type === "connector" && (
                    <div style={{ marginBottom: "16px" }}>
                      <div style={{
                        padding: "10px 12px", borderRadius: "var(--tc-radius-input)",
                        background: "rgba(96,144,208,0.05)", border: "1px solid rgba(96,144,208,0.15)",
                        fontSize: "11px", color: "var(--tc-text-sec)",
                        display: "flex", alignItems: "center", gap: "8px",
                      }}>
                        <Puzzle size={14} color="#6090d0" />
                        {locale === "fr"
                          ? "Ce connecteur se configure dans Dashboard > Skills. Activez le skill correspondant et renseignez l'URL + credentials."
                          : "This connector is configured in Dashboard > Skills. Enable the corresponding skill and enter URL + credentials."}
                      </div>
                    </div>
                  )}

                  {/* Setup guides */}
                  <div>
                    <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
                      {locale === "fr" ? "Guide d'installation" : "Setup guide"}
                    </div>
                    {def.guides.map((guide, gi) => (
                      <div key={gi} style={{ marginBottom: "8px" }}>
                        <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)", marginBottom: "6px" }}>
                          {locale === "fr" ? guide.title : guide.titleEn}
                        </div>
                        {guide.steps.map((step, si) => {
                          const isCode = step.includes("curl") || step.includes("echo") || step.includes("docker") ||
                            step.includes("POST") || step.includes("http") || step.includes("zkg") ||
                            step.includes("<") || step.includes("Module");
                          const displayStep = step.replace(/ADDR/g, syslogAddr.split(":")[0])
                            .replace(/TOKEN/g, source.webhook_token || "YOUR_TOKEN");
                          return (
                            <div key={si} style={{
                              display: "flex", alignItems: "flex-start", gap: "8px",
                              marginBottom: "4px", fontSize: "11px",
                            }}>
                              {isCode ? (
                                <div style={{
                                  flex: 1, padding: "6px 10px", borderRadius: "var(--tc-radius-sm)",
                                  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
                                  fontFamily: "monospace", color: "var(--tc-text-sec)",
                                  display: "flex", alignItems: "center", gap: "6px",
                                  whiteSpace: "pre-wrap", wordBreak: "break-all",
                                }}>
                                  <span style={{ flex: 1 }}>{displayStep}</span>
                                  <CopyButton text={displayStep} />
                                </div>
                              ) : (
                                <div style={{ color: "var(--tc-text-sec)", paddingLeft: "4px" }}>
                                  <span style={{ color: "var(--tc-text-muted)", marginRight: "6px" }}>{si + 1}.</span>
                                  {displayStep}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    ))}
                  </div>

                  {/* Sub-tags (if connected) */}
                  {source.sub_tags && source.sub_tags.length > 0 && (
                    <div style={{ marginTop: "12px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
                      Tags: {source.sub_tags.join(", ")}
                    </div>
                  )}
                </div>
              )}
            </NeuCard>
          );
        })}
      </div>

      {/* Agents section (if any) */}
      {agents.length > 0 && (
        <div style={{ marginTop: "24px" }}>
          <h2 style={{ fontSize: "16px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "10px" }}>
            <Eye size={16} style={{ verticalAlign: "middle", marginRight: "6px" }} />
            {locale === "fr" ? "Agents deployes" : "Deployed agents"}
          </h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: "8px" }}>
            {agents.map((agent, i) => (
              <NeuCard key={i} style={{ padding: "12px 14px", display: "flex", alignItems: "center", gap: "10px" }}>
                <Server size={14} color="var(--tc-green)" />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--tc-text)" }}>{agent.hostname || "unknown"}</div>
                  {agent.last_seen && (
                    <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
                      {locale === "fr" ? "Vu" : "Seen"}: {new Date(agent.last_seen).toLocaleString()}
                    </div>
                  )}
                </div>
                <CheckCircle2 size={12} color="var(--tc-green)" />
              </NeuCard>
            ))}
          </div>
        </div>
      )}

      {/* Refresh button */}
      <div style={{ textAlign: "center", marginTop: "20px" }}>
        <ChromeButton variant="glass" onClick={load}>
          <RefreshCw size={14} style={{ marginRight: "6px" }} />
          {locale === "fr" ? "Actualiser" : "Refresh"}
        </ChromeButton>
      </div>
    </PageShell>
  );
}

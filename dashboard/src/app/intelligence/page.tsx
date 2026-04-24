"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  Shield, AlertTriangle, Target, Users, Network, TrendingUp,
  RefreshCw, Eye, Crosshair, Brain, FileText, Activity,
} from "lucide-react";
import EmbossedButton from "@/components/chrome/EmbossedButton";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import GraphVisualization from "@/components/chrome/GraphVisualization";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";

// ── Types ──

interface ConfidenceScore {
  score: number;
  level: string;
  breakdown: { source: string; weight: number; raw_value: number; weighted_score: number; detail: string }[];
  source_count: number;
  corroboration_bonus: number;
}

interface LateralAnalysis {
  chains: { entry_point: string; hops: string[]; depth: number; final_target: string; target_is_critical: boolean }[];
  fan_outs: { ip_addr: string; country: string; target_count: number; targets: string[]; classification: string }[];
  critical_paths: { entry_point: string; final_target: string }[];
  total_detections: number;
  summary: string;
}

interface CampaignAnalysis {
  campaigns: { id: string; name: string; description: string; source_ips: string[]; attack_count: number; confidence: number }[];
  total_campaigns: number;
  summary: string;
}

interface BlastRadius {
  source_asset: string;
  total_impacted: number;
  critical_impacted: number;
  hops: { hop: number; count: number; assets: { hostname: string; criticality: string }[] }[];
  impact_score: number;
  recommendation: string;
  summary: string;
}

interface AttackPathAnalysis {
  paths: { entry_point: string; target: string; exploitability: number; risk: string; cves_involved: string[] }[];
  total_paths: number;
  critical_paths: number;
  summary: string;
  top_recommendations: string[];
}

interface ThreatActorAnalysis {
  actors: {
    id: string; name: string; origin_country: string; source_ips: string[];
    techniques: string[]; attack_count: number;
    apt_similarity: { apt_name: string; similarity_score: number } | null;
  }[];
  total_actors: number;
  attributed: number;
  summary: string;
}

interface IdentityAnalysis {
  anomalies: { anomaly_type: string; username: string; detail: string; severity: string; confidence: number }[];
  users_tracked: number;
  summary: string;
}

interface AssetStats {
  total_assets: number;
  with_mac: number;
  with_hostname: number;
  coverage: number;
}

// ── Fetch helpers ──

const API = "/api/tc/graph";

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ── Components ──

function Card({ title, icon: Icon, children, color }: {
  title: string; icon: React.ElementType; children: React.ReactNode; color?: string;
}) {
  // Icons on this page are all neutral — color indicates urgency only
  // when the parent passes a red. Anything else becomes muted to fit
  // the SOC palette (red = urgency, green = ok, amber = warning).
  const iconColor = color === "#d03020" || color === "var(--tc-red)" ? "var(--tc-red)" : "var(--tc-text-sec)";
  return (
    <NeuCard style={{ padding: "20px", minHeight: "180px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "14px" }}>
        <Icon size={14} color={iconColor} />
        <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.14em" }}>
          {title}
        </span>
      </div>
      {children}
    </NeuCard>
  );
}

function StatBadge({ value, label, color }: { value: string | number; label: string; color?: string }) {
  // Only reds and greens survive — anything fancier is flattened to text.
  const isRed = color === "#d03020" || color === "var(--tc-red)";
  const isGreen = color === "#30a050" || color === "var(--tc-green)";
  const isAmber = color === "#d09020" || color === "#d06020" || color === "var(--tc-amber)";
  const textColor = isRed ? "var(--tc-red)" : isGreen ? "var(--tc-green)" : isAmber ? "var(--tc-amber)" : "var(--tc-text)";
  return (
    <div style={{ textAlign: "center", padding: "4px" }}>
      <div style={{ fontSize: "22px", fontWeight: 800, color: textColor, fontVariantNumeric: "tabular-nums" }}>{value}</div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.14em" }}>{label}</div>
    </div>
  );
}

function ConfidenceBar({ score, level }: { score: number; level: string }) {
  const color = score >= 80 ? "var(--tc-red)" : score >= 50 ? "var(--tc-amber)" : score >= 30 ? "var(--tc-text-sec)" : "var(--tc-green)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
      <div style={{ flex: 1, height: "4px", background: "var(--tc-input)" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color, transition: "width 500ms" }} />
      </div>
      <span style={{ fontSize: "12px", fontWeight: 700, color, minWidth: "46px", fontVariantNumeric: "tabular-nums" }}>{score}/100</span>
      <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.14em" }}>{level}</span>
    </div>
  );
}

function RiskBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    critical: "var(--tc-red)",
    high: "var(--tc-red)",
    medium: "var(--tc-amber)",
    low: "var(--tc-green)",
  };
  const c = colors[risk] || "var(--tc-text-muted)";
  return (
    <span style={{
      fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.14em",
      padding: "2px 8px", color: c, border: `1px solid ${c}`, background: "transparent",
    }}>{risk}</span>
  );
}

// ── Main Page ──

export default function IntelligencePage() {
  const locale = useLocale();
  const [lateral, setLateral] = useState<LateralAnalysis | null>(null);
  const [campaigns, setCampaigns] = useState<CampaignAnalysis | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPathAnalysis | null>(null);
  const [actors, setActors] = useState<ThreatActorAnalysis | null>(null);
  const [identity, setIdentity] = useState<IdentityAnalysis | null>(null);
  const [assetStats, setAssetStats] = useState<AssetStats | null>(null);
  const [blastAsset, setBlastAsset] = useState("");
  const [blast, setBlast] = useState<BlastRadius | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [lat, camp, paths, act, ident, stats] = await Promise.all([
        fetchJson<LateralAnalysis>(`${API}/lateral`),
        fetchJson<CampaignAnalysis>(`${API}/campaigns`),
        fetchJson<AttackPathAnalysis>(`${API}/attack-paths`),
        fetchJson<ThreatActorAnalysis>(`${API}/threat-actors`),
        fetchJson<IdentityAnalysis>(`${API}/identity`),
        fetchJson<AssetStats>(`${API}/assets/stats`),
      ]);
      setLateral(lat);
      setCampaigns(camp);
      setAttackPaths(paths);
      setActors(act);
      setIdentity(ident);
      setAssetStats(stats);
      setLastRefresh(new Date().toLocaleTimeString());
      setError(null);
    } catch {
      setError(tr("backendNotAccessible", locale));
    }
    setLoading(false);
  }, []);

  const loadBlast = useCallback(async () => {
    if (!blastAsset.trim()) return;
    const br = await fetchJson<BlastRadius>(`${API}/blast-radius/${encodeURIComponent(blastAsset)}`);
    setBlast(br);
  }, [blastAsset]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { loadBlast(); }, [loadBlast]);

  return (
    <PageShell
      title="Graph Intelligence"
      subtitle={`Analyse en temps réel depuis Apache AGE + STIX 2.1${lastRefresh ? ` · dernière actualisation ${lastRefresh}` : ""}`}
      right={
        <EmbossedButton onClick={refresh} disabled={loading}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Actualiser
        </EmbossedButton>
      }
    >
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      {/* Top stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "12px", marginBottom: "20px" }}>
        <NeuCard style={{ padding: "16px" }}>
          <StatBadge value={assetStats?.total_assets ?? "—"} label="Assets" color="#30a0d0" />
        </NeuCard>
        <NeuCard style={{ padding: "16px" }}>
          <StatBadge value={lateral?.total_detections ?? "—"} label="Lateral" color={lateral?.total_detections ? "#d03020" : "#30a050"} />
        </NeuCard>
        <NeuCard style={{ padding: "16px" }}>
          <StatBadge value={campaigns?.total_campaigns ?? "—"} label="Campagnes" color={campaigns?.total_campaigns ? "#d06020" : "#30a050"} />
        </NeuCard>
        <NeuCard style={{ padding: "16px" }}>
          <StatBadge value={actors?.total_actors ?? "—"} label="Acteurs" color="#9060d0" />
        </NeuCard>
        <NeuCard style={{ padding: "16px" }}>
          <StatBadge value={identity?.anomalies?.length ?? "—"} label="Anomalies ID" color={identity?.anomalies?.length ? "#d03020" : "#30a050"} />
        </NeuCard>
      </div>

      {/* Attack graph */}
      <div style={{ marginBottom: "16px" }}>
        <GraphVisualization />
      </div>

      {/* Main grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>

        {/* Attack Paths */}
        <Card title="Chemins d'attaque" icon={Crosshair} color="#d03020">
          {attackPaths && attackPaths.paths.length > 0 ? (
            <div>
              <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "10px" }}>
                {attackPaths.total_paths} chemins ({attackPaths.critical_paths} critiques)
              </div>
              {attackPaths.paths.slice(0, 5).map((p, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "center", gap: "8px", padding: "8px 10px",
                  marginBottom: "6px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)",
                  border: "1px solid var(--tc-border-light)",
                }}>
                  <RiskBadge risk={p.risk} />
                  <span style={{ fontSize: "11px", color: "var(--tc-red)", fontFamily: "monospace" }}>{p.entry_point}</span>
                  <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>&rarr;</span>
                  <span style={{ fontSize: "11px", color: "var(--tc-text)", fontWeight: 600 }}>{p.target}</span>
                  <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginLeft: "auto" }}>{Math.round(p.exploitability)}%</span>
                </div>
              ))}
              {attackPaths.top_recommendations.length > 0 && (
                <div style={{ marginTop: "10px", padding: "8px", borderRadius: "var(--tc-radius-sm)", background: "rgba(208,48,32,0.05)", border: "1px solid rgba(208,48,32,0.1)" }}>
                  <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", marginBottom: "4px" }}>{tr("recommendations", locale)}</div>
                  {attackPaths.top_recommendations.map((r, i) => (
                    <div key={i} style={{ fontSize: "10px", color: "var(--tc-text-sec)", lineHeight: "1.5" }}>{i + 1}. {r}</div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "var(--tc-text-faint)", textAlign: "center", padding: "30px 0" }}>
              Aucune progression d&apos;attaque detect&eacute;
            </div>
          )}
        </Card>

        {/* Threat Actors */}
        <Card title="Acteurs de menace" icon={Users} color="#9060d0">
          {actors && actors.actors.length > 0 ? (
            <div>
              <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "10px" }}>
                {actors.total_actors} acteur(s) &middot; {actors.attributed} attribution(s)
              </div>
              {actors.actors.slice(0, 4).map((a, i) => (
                <div key={i} style={{
                  padding: "10px", marginBottom: "6px", borderRadius: "var(--tc-radius-input)",
                  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
                }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{a.name}</span>
                    <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>{a.origin_country}</span>
                  </div>
                  <div style={{ display: "flex", gap: "4px", marginTop: "6px", flexWrap: "wrap" }}>
                    {a.techniques.slice(0, 5).map((t, j) => (
                      <span key={j} style={{
                        fontSize: "9px", padding: "2px 6px", borderRadius: "3px",
                        background: "rgba(144,96,208,0.1)", color: "var(--tc-purple)", border: "1px solid rgba(144,96,208,0.2)",
                      }}>{t}</span>
                    ))}
                  </div>
                  {a.apt_similarity && a.apt_similarity.similarity_score > 30 && (
                    <div style={{ fontSize: "10px", color: "var(--tc-amber)", marginTop: "6px" }}>
                      Correspond a {a.apt_similarity.apt_name} ({a.apt_similarity.similarity_score}%)
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "var(--tc-text-faint)", textAlign: "center", padding: "30px 0" }}>
              Aucun acteur profil&eacute;
            </div>
          )}
        </Card>

        {/* Blast Radius */}
        <Card title="Blast Radius" icon={Target} color="#d06020">
          <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
            <input
              type="text" value={blastAsset}
              onChange={(e) => setBlastAsset(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && loadBlast()}
              placeholder="Asset ID (ex: srv-prod-01)"
              style={{
                flex: 1, padding: "6px 10px", borderRadius: "var(--tc-radius-sm)", fontSize: "11px",
                background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                color: "var(--tc-text)", outline: "none",
              }}
            />
            <button onClick={loadBlast} style={{
              padding: "6px 12px", borderRadius: "var(--tc-radius-sm)", fontSize: "10px", fontWeight: 600,
              background: "transparent", border: "1px solid var(--tc-red)",
              color: "var(--tc-red)", cursor: "pointer",
            }}>{tr("calculate", locale)}</button>
          </div>
          {blast && (
            <div>
              <div style={{ display: "flex", gap: "16px", marginBottom: "10px" }}>
                <StatBadge value={blast.total_impacted} label={locale === "fr" ? "Impactés" : "Impacted"} color="#d06020" />
                <StatBadge value={blast.critical_impacted} label={locale === "fr" ? "Critiques" : "Critical"} color="#d03020" />
                <StatBadge value={Math.round(blast.impact_score)} label="Score" color="#d06020" />
              </div>
              {blast.hops.filter(h => h.count > 0).map((h, i) => (
                <div key={i} style={{
                  padding: "6px 10px", marginBottom: "4px", borderRadius: "var(--tc-radius-sm)",
                  background: "var(--tc-surface-alt)",
                  border: "1px solid var(--tc-border)",
                  fontSize: "11px", color: "var(--tc-text)",
                }}>
                  <strong>Hop {h.hop}</strong> &mdash; {h.count} asset(s)
                  {h.assets && h.assets.length > 0 && (
                    <span style={{ color: "var(--tc-text-muted)" }}> ({h.assets.map((a: any) => typeof a === "string" ? a : a.hostname).join(", ")})</span>
                  )}
                </div>
              ))}
              <div style={{ fontSize: "10px", color: "var(--tc-red)", marginTop: "8px", fontStyle: "italic" }}>
                {blast.recommendation}
              </div>
            </div>
          )}
          {blast && blast.total_impacted === 0 && (
            <div style={{ fontSize: "12px", color: "var(--tc-text-faint)", textAlign: "center", padding: "20px 0" }}>
              Asset isol&eacute; &mdash; pas d&apos;impact collat&eacute;ral
            </div>
          )}
        </Card>

        {/* Lateral Movement */}
        <Card title="Mouvement lateral" icon={Network} color="#d03020">
          {lateral && lateral.total_detections > 0 ? (
            <div>
              <div style={{ fontSize: "11px", color: "var(--tc-red)", fontWeight: 600, marginBottom: "10px" }}>
                {lateral.total_detections} detection(s)
              </div>
              {lateral.chains.slice(0, 3).map((c, i) => (
                <div key={i} style={{
                  padding: "8px 10px", marginBottom: "4px", borderRadius: "var(--tc-radius-sm)",
                  background: "rgba(208,48,32,0.05)", border: "1px solid rgba(208,48,32,0.1)",
                  fontSize: "11px",
                }}>
                  <span style={{ color: "var(--tc-red)", fontFamily: "monospace" }}>{c.entry_point}</span>
                  {c.hops.map((h, j) => (
                    <span key={j}><span style={{ color: "var(--tc-text-muted)" }}> &rarr; </span><span style={{ color: "var(--tc-text)" }}>{h}</span></span>
                  ))}
                  {c.target_is_critical && <RiskBadge risk="critical" />}
                </div>
              ))}
              {lateral.fan_outs.slice(0, 3).map((f, i) => (
                <div key={`fo-${i}`} style={{
                  padding: "8px 10px", marginBottom: "4px", borderRadius: "var(--tc-radius-sm)",
                  background: "rgba(208,96,32,0.05)", border: "1px solid rgba(208,96,32,0.1)",
                  fontSize: "11px", color: "var(--tc-amber)",
                }}>
                  Fan-out: {f.ip_addr} ({f.country}) &rarr; {f.target_count} assets
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "var(--tc-green)", textAlign: "center", padding: "30px 0" }}>
              Aucun mouvement lat&eacute;ral d&eacute;tect&eacute;
            </div>
          )}
        </Card>

        {/* Campaigns */}
        <Card title="Campagnes detectees" icon={Eye} color="#d09020">
          {campaigns && campaigns.campaigns.length > 0 ? (
            <div>
              {campaigns.campaigns.slice(0, 4).map((c, i) => (
                <div key={i} style={{
                  padding: "10px", marginBottom: "6px", borderRadius: "var(--tc-radius-input)",
                  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
                }}>
                  <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{c.name}</div>
                  <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "4px" }}>{c.description}</div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: "6px" }}>
                    <span style={{ fontSize: "10px", color: "var(--tc-amber)" }}>{c.attack_count} attaques</span>
                    <ConfidenceBar score={c.confidence} level="" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "var(--tc-text-faint)", textAlign: "center", padding: "30px 0" }}>
              Aucune campagne coordonn&eacute;e
            </div>
          )}
        </Card>

        {/* Identity Anomalies */}
        <Card title="Anomalies utilisateurs" icon={Brain} color="#3080d0">
          {identity && identity.anomalies.length > 0 ? (
            <div>
              <Link href="/users" style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "10px", display: "block", textDecoration: "none" }}>
                {identity.users_tracked} utilisateurs suivis →
              </Link>
              {identity.anomalies.slice(0, 5).map((a, i) => (
                <Link
                  key={i}
                  href={`/users/${encodeURIComponent(a.username)}`}
                  style={{
                    display: "block", padding: "8px 10px", marginBottom: "4px",
                    borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)",
                    border: "1px solid var(--tc-border-light)", fontSize: "11px",
                    textDecoration: "none",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <RiskBadge risk={a.severity} />
                    <span style={{ color: "var(--tc-text)", fontWeight: 600 }}>{a.username}</span>
                  </div>
                  <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "4px" }}>{a.detail}</div>
                </Link>
              ))}
            </div>
          ) : (
            <Link href="/users" style={{ fontSize: "12px", color: "var(--tc-green)", textAlign: "center", padding: "30px 0", display: "block", textDecoration: "none" }}>
              {identity?.users_tracked ?? 0} utilisateurs &middot; aucune anomalie →
            </Link>
          )}
        </Card>

      </div>

      {/* NIS2 Report button */}
      <div style={{ marginTop: "20px", display: "flex", gap: "12px", justifyContent: "center" }}>
        <EmbossedButton onClick={async () => {
          const report = await fetchJson(`${API}/supply-chain/nis2`);
          if (report) {
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = "threatclaw-nis2-report.json"; a.click();
            URL.revokeObjectURL(url);
          }
        }}>
          <FileText size={14} /> Rapport NIS2 Article 21
        </EmbossedButton>
        <EmbossedButton onClick={async () => {
          await fetch(`${API}/coa/seed`, { method: "POST" });
          alert(locale === "fr" ? "Mitigations MITRE chargées dans le graphe" : "MITRE mitigations loaded into graph");
        }}>
          <Shield size={14} /> Charger playbooks MITRE
        </EmbossedButton>
      </div>
    </PageShell>
  );
}

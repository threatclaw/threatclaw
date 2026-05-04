"use client";

// Prédiction d'attaque — vue stratégique avec 2 onglets :
//
// 1. Prédiction (Module B, défaut) : analyse statique CVE-chain.
//    Source : GET /api/tc/graph/attack-paths (predict_attack_paths()).
//    Calcule des paths à partir de l'inventaire + CVE + criticité, sans
//    avoir besoin d'activité observée. Donne au RSSI/DSI sa liste de
//    "ce qui est exposé et patcher en priorité".
//
// 2. Activité observée (Module A) : Phase G2/G3 graph-walker.
//    Source : GET /api/tc/security/attack-paths + /choke-points
//            POST /api/tc/security/attack-paths/recompute
//    Marche dans un graphe de connexions effectivement observées
//    (LATERAL_PATH dérivés des LOGGED_IN, ATTACKS depuis sigma).
//    Vue analyste : "qu'est-ce qui s'est passé latéralement".

import React, { useEffect, useState, useCallback } from "react";
import { PageShell } from "@/components/chrome/PageShell";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import {
  Shield,
  Target,
  TrendingUp,
  RefreshCw,
  ChevronRight,
  AlertTriangle,
  Server,
  Activity,
  ArrowRight,
  ShieldAlert,
} from "lucide-react";

// ── Module B types — mirror src/graph/attack_path.rs ────────────────

interface PredPathNode {
  asset: string;
  hostname: string;
  role: string;
  cvss_max: number;
  has_kev: boolean;
}

interface PredAttackPath {
  entry_point: string;
  path: PredPathNode[];
  target: string;
  exploitability: number;
  cves_involved: string[];
  mitre_techniques: string[];
  risk: string;
}

interface PredAnalysis {
  paths: PredAttackPath[];
  total_paths: number;
  critical_paths: number;
  summary: string;
  top_recommendations: string[];
}

// ── Module A types — Phase G2/G3 ───────────────────────────────────

interface ObsAttackPath {
  run_id: string;
  src_asset: string;
  dst_asset: string;
  path_assets: string[];
  hops: number;
  score: number;
  epss_max: number | null;
  has_kev: boolean;
  cves_chain: string[];
  mitre_techniques: string[];
  explanation: string | null;
  computed_at: string;
}

interface ChokePoint {
  asset: string;
  paths_through: number;
  weighted_score: number;
  top_targets: string[];
}

// ── Helpers ─────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, { bg: string; fg: string; border: string }> = {
  critical: { bg: "rgba(208,48,32,0.12)", fg: "#e04040", border: "rgba(208,48,32,0.45)" },
  high:     { bg: "rgba(208,144,32,0.10)", fg: "#d09020", border: "rgba(208,144,32,0.40)" },
  medium:   { bg: "rgba(48,128,208,0.10)", fg: "#3080d0", border: "rgba(48,128,208,0.35)" },
  low:      { bg: "rgba(96,160,96,0.10)", fg: "#60a060", border: "rgba(96,160,96,0.30)" },
};

function riskColor(r: string) {
  return RISK_COLORS[r?.toLowerCase()] ?? RISK_COLORS.medium;
}

// ── Page ────────────────────────────────────────────────────────────

type Tab = "prediction" | "observed";

export default function ThreatMapPage() {
  const [tab, setTab] = useState<Tab>("prediction");
  const [error, setError] = useState<string | null>(null);

  return (
    <PageShell
      title="Prédiction d'attaque"
      subtitle="Chemins d'attaque probables vers les assets critiques + fixes prioritaires"
    >
      {error && <ErrorBanner message={error} />}

      {/* Tabs */}
      <div
        style={{
          display: "flex",
          gap: 4,
          marginBottom: 18,
          borderBottom: "1px solid var(--tc-border)",
        }}
      >
        <TabButton active={tab === "prediction"} onClick={() => setTab("prediction")}>
          Prédiction
        </TabButton>
        <TabButton active={tab === "observed"} onClick={() => setTab("observed")}>
          Activité observée
        </TabButton>
      </div>

      {tab === "prediction" ? (
        <PredictionPanel onError={setError} />
      ) : (
        <ObservedPanel onError={setError} />
      )}
    </PageShell>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "9px 16px",
        background: "transparent",
        border: "none",
        borderBottom: active ? "2px solid var(--tc-red)" : "2px solid transparent",
        color: active ? "var(--tc-text)" : "var(--tc-text-muted)",
        fontSize: 12,
        letterSpacing: "0.06em",
        cursor: "pointer",
        fontFamily: "inherit",
        marginBottom: -1,
      }}
    >
      {children}
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Module B — Prédiction (CVE-chain analyzer)
// ═══════════════════════════════════════════════════════════════════

function PredictionPanel({ onError }: { onError: (e: string | null) => void }) {
  const [data, setData] = useState<PredAnalysis | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    onError(null);
    try {
      const r = await fetch("/api/tc/graph/attack-paths", { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as PredAnalysis;
      setData(j);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, [onError]);

  useEffect(() => {
    load();
  }, [load]);

  const paths = data?.paths ?? [];
  const totalCves = new Set(paths.flatMap((p) => p.cves_involved ?? [])).size;

  return (
    <div>
      {/* Header refresh */}
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
        <ChromeButton onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
        </ChromeButton>
      </div>

      {/* Hero stats */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr)",
          gap: 14,
          marginBottom: 18,
        }}
      >
        <StatCard label="Chemins prédits" value={data?.total_paths ?? 0} icon={<Activity size={14} />} />
        <StatCard
          label="Critiques"
          value={data?.critical_paths ?? 0}
          icon={<AlertTriangle size={14} />}
          accent={(data?.critical_paths ?? 0) > 0 ? "#e04040" : undefined}
        />
        <StatCard label="CVE impliquées" value={totalCves} icon={<ShieldAlert size={14} />} />
      </div>

      {/* Top recommendations */}
      {data?.top_recommendations?.length ? (
        <NeuCard accent="amber" style={{ marginBottom: 18 }}>
          <div style={{ padding: "1rem" }}>
            <h2 style={{ fontSize: "1rem", marginBottom: "0.6rem", display: "flex", gap: 6, alignItems: "center" }}>
              <Shield size={16} /> Recommandations prioritaires
            </h2>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.7 }}>
              {data.top_recommendations.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </NeuCard>
      ) : null}

      {/* Path list */}
      {loading && !data ? (
        <NeuCard>
          <div style={{ padding: 24, textAlign: "center", color: "var(--tc-text-muted)" }}>Chargement…</div>
        </NeuCard>
      ) : paths.length === 0 ? (
        <NeuCard>
          <div style={{ padding: "2rem", textAlign: "center" }}>
            <Target size={48} style={{ opacity: 0.4, margin: "0 auto 1rem" }} />
            <h3 style={{ marginBottom: "0.5rem" }}>Aucun chemin d&apos;attaque prédit</h3>
            <p style={{ opacity: 0.7, marginBottom: "0.75rem", fontSize: 12, lineHeight: 1.6 }}>
              La prédiction CVE-chain a besoin de :
            </p>
            <ul style={{ opacity: 0.7, fontSize: 12, textAlign: "left", maxWidth: 540, margin: "0 auto", lineHeight: 1.7 }}>
              <li>Au moins un asset déclaré <code>criticality = critical</code> (la cible).</li>
              <li>Des findings CVE actifs sur des assets accessibles depuis l&apos;extérieur ou pivots internes.</li>
              <li>Pour les paths externes : un asset <code>exposure_class = internet</code> ou DMZ.</li>
            </ul>
          </div>
        </NeuCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {paths.map((p, idx) => (
            <PredPathCard key={idx} path={p} />
          ))}
        </div>
      )}
    </div>
  );
}

function PredPathCard({ path }: { path: PredAttackPath }) {
  const c = riskColor(path.risk);
  const expScore = Math.round(path.exploitability ?? 0);
  return (
    <NeuCard style={{ borderLeft: `3px solid ${c.border}` }}>
      <div style={{ padding: "1rem" }}>
        {/* Header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 10,
            marginBottom: 14,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span
              style={{
                fontSize: 9,
                letterSpacing: "0.16em",
                textTransform: "uppercase",
                padding: "3px 9px",
                background: c.bg,
                color: c.fg,
                border: `1px solid ${c.border}`,
                borderRadius: 3,
              }}
            >
              {path.risk}
            </span>
            <div style={{ fontSize: 11, color: "var(--tc-text-muted)", letterSpacing: "0.06em" }}>
              exploitabilité{" "}
              <span style={{ color: c.fg, fontVariantNumeric: "tabular-nums" }}>{expScore}/100</span>
            </div>
          </div>
          <div style={{ fontSize: 10, color: "var(--tc-text-muted)", letterSpacing: "0.06em" }}>
            {(path.cves_involved?.length ?? 0)} CVE · {(path.mitre_techniques?.length ?? 0)} ATT&CK
          </div>
        </div>

        {/* Path chain */}
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, marginBottom: 14 }}>
          {path.path?.map((node, i) => (
            <React.Fragment key={i}>
              {i > 0 && <ArrowRight size={14} style={{ color: "var(--tc-text-muted)", flexShrink: 0 }} />}
              <NodePill node={node} />
            </React.Fragment>
          ))}
        </div>

        {/* CVEs + techniques */}
        {(path.cves_involved?.length || path.mitre_techniques?.length) && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
              gap: 14,
              paddingTop: 12,
              borderTop: "1px dashed var(--tc-border)",
            }}
          >
            <div>
              <div
                style={{
                  fontSize: 9,
                  letterSpacing: "0.16em",
                  textTransform: "uppercase",
                  color: "var(--tc-text-muted)",
                  marginBottom: 6,
                }}
              >
                CVE
              </div>
              <div style={{ fontSize: 11, lineHeight: 1.7, wordBreak: "break-all" }}>
                {path.cves_involved?.length ? (
                  <>
                    {path.cves_involved.slice(0, 6).join(" · ")}
                    {path.cves_involved.length > 6 && (
                      <span style={{ color: "var(--tc-text-muted)" }}>
                        {" "}+{path.cves_involved.length - 6} autres
                      </span>
                    )}
                  </>
                ) : (
                  <span style={{ color: "var(--tc-text-muted)" }}>—</span>
                )}
              </div>
            </div>
            <div>
              <div
                style={{
                  fontSize: 9,
                  letterSpacing: "0.16em",
                  textTransform: "uppercase",
                  color: "var(--tc-text-muted)",
                  marginBottom: 6,
                }}
              >
                MITRE ATT&CK
              </div>
              <div style={{ fontSize: 11, lineHeight: 1.7, wordBreak: "break-all" }}>
                {path.mitre_techniques?.length ? (
                  path.mitre_techniques.slice(0, 6).join(" · ")
                ) : (
                  <span style={{ color: "var(--tc-text-muted)" }}>—</span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </NeuCard>
  );
}

function NodePill({ node }: { node: PredPathNode }) {
  const isTarget = node.role === "target";
  const isEntry = node.role === "entry";
  const accent = isTarget ? "#e04040" : isEntry ? "#3080d0" : "var(--tc-text)";
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "5px 10px",
        background: "var(--tc-surface-2)",
        border: `1px solid ${node.has_kev ? "rgba(208,48,32,0.45)" : "var(--tc-border)"}`,
        borderRadius: 3,
        fontSize: 11,
      }}
    >
      <Server size={12} style={{ color: accent }} />
      <span style={{ color: "var(--tc-text)" }}>{node.hostname || node.asset}</span>
      {node.cvss_max > 0 && (
        <span style={{ fontSize: 9, color: "var(--tc-text-muted)", fontVariantNumeric: "tabular-nums" }}>
          CVSS {node.cvss_max.toFixed(1)}
        </span>
      )}
      {node.has_kev && (
        <span
          style={{
            fontSize: 9,
            color: "#e04040",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          KEV
        </span>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  accent?: string;
}) {
  return (
    <NeuCard>
      <div style={{ padding: 16 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            color: "var(--tc-text-muted)",
            fontSize: 9,
            letterSpacing: "0.22em",
            textTransform: "uppercase",
            marginBottom: 8,
          }}
        >
          {icon}
          {label}
        </div>
        <div
          style={{
            fontSize: 28,
            fontVariantNumeric: "tabular-nums",
            color: accent ?? "var(--tc-text)",
          }}
        >
          {value}
        </div>
      </div>
    </NeuCard>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Module A — Activité observée (Phase G2/G3 graph-walker)
// ═══════════════════════════════════════════════════════════════════

function ObservedPanel({ onError }: { onError: (e: string | null) => void }) {
  const [paths, setPaths] = useState<ObsAttackPath[]>([]);
  const [chokes, setChokes] = useState<ChokePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [recomputing, setRecomputing] = useState(false);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    onError(null);
    try {
      const [pathsRes, chokesRes] = await Promise.all([
        fetch("/api/tc/security/attack-paths?limit=20", { cache: "no-store" }),
        fetch("/api/tc/security/choke-points?limit=10", { cache: "no-store" }),
      ]);
      if (!pathsRes.ok) throw new Error(`paths HTTP ${pathsRes.status}`);
      if (!chokesRes.ok) throw new Error(`choke HTTP ${chokesRes.status}`);
      const pathsJson = await pathsRes.json();
      const chokesJson = await chokesRes.json();
      setPaths(pathsJson.paths || []);
      setChokes(chokesJson.choke_points || []);
      if (pathsJson.paths?.[0]?.computed_at) {
        setLastRunAt(pathsJson.paths[0].computed_at);
      }
    } catch (e) {
      onError(e instanceof Error ? e.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, [onError]);

  const recompute = useCallback(async () => {
    setRecomputing(true);
    onError(null);
    try {
      const r = await fetch("/api/tc/security/attack-paths/recompute", { method: "POST" });
      if (!r.ok) throw new Error(`recompute HTTP ${r.status}`);
      setTimeout(() => load(), 800);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Erreur de recalcul");
    } finally {
      setRecomputing(false);
    }
  }, [load, onError]);

  useEffect(() => {
    load();
  }, [load]);

  const empty = !loading && paths.length === 0 && chokes.length === 0;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, gap: 8 }}>
        <div style={{ fontSize: 11, color: "var(--tc-text-muted)", lineHeight: 1.5 }}>
          Chemins dérivés des connexions effectivement observées (auth events, sigma alerts).
          {lastRunAt && (
            <> · dernier calcul {new Date(lastRunAt).toLocaleString("fr-FR")}</>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <ChromeButton onClick={load} disabled={loading || recomputing}>
            <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
          </ChromeButton>
          <ChromeButton onClick={recompute} disabled={recomputing}>
            <TrendingUp size={14} /> {recomputing ? "Calcul…" : "Recalculer"}
          </ChromeButton>
        </div>
      </div>

      {empty && (
        <NeuCard>
          <div style={{ padding: "2rem", textAlign: "center" }}>
            <Activity size={48} style={{ opacity: 0.4, margin: "0 auto 1rem" }} />
            <h3 style={{ marginBottom: "0.5rem" }}>Aucune activité corrélée</h3>
            <p style={{ opacity: 0.7, marginBottom: "0.75rem", fontSize: 12, lineHeight: 1.6 }}>
              Le graph-walker a besoin de :
            </p>
            <ul style={{ opacity: 0.7, fontSize: 12, textAlign: "left", maxWidth: 540, margin: "0 auto", lineHeight: 1.7 }}>
              <li>
                Des événements <code>LOGGED_IN</code> ingérés (Wazuh, AD, Windows Event 4624)
                pour dériver les <code>LATERAL_PATH</code> entre hosts partageant des
                comptes.
              </li>
              <li>
                Ou des sigma alerts d&apos;attaque pour créer des edges <code>ATTACKS</code>{" "}
                source→cible.
              </li>
              <li>Au moins un asset <code>critical</code> (cible).</li>
            </ul>
          </div>
        </NeuCard>
      )}

      {chokes.length > 0 && (
        <NeuCard accent="amber" style={{ marginBottom: 12 }}>
          <div style={{ padding: "1rem" }}>
            <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
              <Shield size={16} /> Top {Math.min(chokes.length, 3)} fixes prioritaires
              <span style={{ marginLeft: "auto", fontSize: "0.78rem", opacity: 0.55 }}>
                durcir ces nœuds = casser le plus de chemins
              </span>
            </h2>
            {chokes.slice(0, 3).map((c, i) => (
              <div
                key={c.asset}
                style={{
                  padding: "0.7rem 0",
                  borderBottom:
                    i < Math.min(chokes.length, 3) - 1 ? "1px solid rgba(255,255,255,0.05)" : "none",
                  fontSize: "0.85rem",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <strong>
                    #{i + 1} {c.asset}
                  </strong>
                  <span style={{ opacity: 0.7 }}>
                    casse <strong>{c.paths_through}</strong> chemins
                    {c.weighted_score > 0 && <> · score pondéré {c.weighted_score.toFixed(2)}</>}
                  </span>
                </div>
                {c.top_targets.length > 0 && (
                  <div style={{ opacity: 0.6, fontSize: "0.78rem", marginTop: "0.2rem" }}>
                    menace les crown jewels : {c.top_targets.join(", ")}
                  </div>
                )}
              </div>
            ))}
            {chokes.length > 3 && (
              <div style={{ opacity: 0.55, fontSize: "0.78rem", marginTop: "0.5rem" }}>
                + {chokes.length - 3} choke points additionnels
              </div>
            )}
          </div>
        </NeuCard>
      )}

      {paths.length > 0 && (
        <NeuCard>
          <div style={{ padding: "1rem" }}>
            <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
              <AlertTriangle size={16} /> Chemins observés
            </h2>
            {paths.map((p, i) => (
              <div
                key={`${p.src_asset}-${p.dst_asset}-${i}`}
                style={{
                  padding: "0.7rem 0",
                  borderBottom: i < paths.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none",
                  fontSize: "0.85rem",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <strong>
                    #{i + 1} {p.src_asset}
                    <ChevronRight size={12} style={{ display: "inline", opacity: 0.5 }} />
                    {p.dst_asset}
                  </strong>
                  <span style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                    {p.has_kev && (
                      <span
                        style={{
                          fontSize: "0.7rem",
                          padding: "0.1rem 0.45rem",
                          borderRadius: 4,
                          background: "rgba(220,80,80,0.2)",
                        }}
                      >
                        KEV
                      </span>
                    )}
                    <strong>score {p.score.toFixed(2)}</strong>
                  </span>
                </div>
                <div style={{ opacity: 0.7, fontSize: "0.78rem", marginTop: "0.25rem" }}>
                  {p.path_assets.join(" → ")} ({p.hops} hops)
                </div>
                {p.explanation && (
                  <div
                    style={{
                      opacity: 0.6,
                      fontSize: "0.72rem",
                      marginTop: "0.25rem",
                      fontStyle: "italic",
                    }}
                  >
                    {p.explanation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </NeuCard>
      )}
    </div>
  );
}

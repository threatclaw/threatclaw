"use client";

// /threat-map — Phase G2 + G3 visualisation.
//
// Affiche :
// - Top 3 fixes prioritaires (choke points G3) en bandeau action-first
// - Top-20 chemins d'attaque les plus probables (G2)
// - Bouton "Recalculer" qui POST /api/tc/security/attack-paths/recompute
//
// C'est ce que vend le tier "Defend" du pricing : "voici tes 3 chemins
// d'attaque les plus probables + voici les 3 trucs à fixer cette semaine".

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
} from "lucide-react";

interface AttackPath {
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

export default function ThreatMapPage() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [chokes, setChokes] = useState<ChokePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [recomputing, setRecomputing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
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
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  const recompute = useCallback(async () => {
    setRecomputing(true);
    setError(null);
    try {
      const r = await fetch("/api/tc/security/attack-paths/recompute", {
        method: "POST",
      });
      if (!r.ok) throw new Error(`recompute HTTP ${r.status}`);
      // Wait a beat then reload
      setTimeout(() => load(), 500);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Recompute failed");
    } finally {
      setRecomputing(false);
    }
  }, [load]);

  useEffect(() => {
    load();
  }, [load]);

  const empty = !loading && paths.length === 0 && chokes.length === 0;

  return (
    <PageShell
      title="Carte des menaces"
      subtitle="Chemins d'attaque probables + fixes prioritaires"
      right={
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <ChromeButton onClick={load} disabled={loading || recomputing}>
            <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
          </ChromeButton>
          <ChromeButton onClick={recompute} disabled={recomputing}>
            <TrendingUp size={14} /> {recomputing ? "Calcul…" : "Recalculer"}
          </ChromeButton>
        </div>
      }
    >
      <div style={{ padding: "1rem 0" }}>
        {error && <ErrorBanner message={error} />}

        {empty && (
          <NeuCard>
            <div style={{ padding: "2rem", textAlign: "center" }}>
              <Target size={48} style={{ opacity: 0.4, margin: "0 auto 1rem" }} />
              <h3 style={{ marginBottom: "0.5rem" }}>Aucun chemin d&apos;attaque calculé</h3>
              <p style={{ opacity: 0.7, marginBottom: "0.75rem" }}>
                Le batch de prédiction tourne automatiquement toutes les 6 h.
                Tu peux aussi le lancer manuellement avec le bouton « Recalculer ».
              </p>
              <p style={{ opacity: 0.7, marginBottom: "0.75rem", fontSize: "0.9rem" }}>
                <strong>Causes habituelles à vide :</strong>
              </p>
              <ul style={{ opacity: 0.7, fontSize: "0.85rem", textAlign: "left", maxWidth: "560px", margin: "0 auto", lineHeight: 1.6 }}>
                <li>
                  Aucun edge <code>LATERAL_PATH</code> ni <code>ATTACKS</code> dans
                  le graph — le batch dérive maintenant les LATERAL_PATH depuis
                  les événements <code>LOGGED_IN</code> (Wazuh, AD), il faut
                  donc des logs d&apos;authentification ingérés.
                </li>
                <li>
                  Aucune cible critique : marque tes assets sensibles (DC,
                  serveur de fichiers, firewall) en <code>critical</code> ou{" "}
                  <code>high</code> via la fiche asset (onglet Résumé →
                  Criticité).
                </li>
                <li>
                  Aucune source exposée : le batch ne considère que les assets
                  dont <code>exposure_class</code> est <code>internet</code>,{" "}
                  <code>dmz</code> ou <code>vlan_dev</code> (heuristique IP au
                  démarrage du batch).
                </li>
              </ul>
            </div>
          </NeuCard>
        )}

        {/* Top fixes prioritaires (choke points G3) */}
        {chokes.length > 0 && (
          <NeuCard accent="amber">
            <div style={{ padding: "1rem" }}>
              <h2
                style={{
                  fontSize: "1rem",
                  marginBottom: "0.75rem",
                  display: "flex",
                  gap: 6,
                  alignItems: "center",
                }}
              >
                <Shield size={16} /> Top {Math.min(chokes.length, 3)} fixes prioritaires
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: "0.78rem",
                    opacity: 0.55,
                  }}
                >
                  durcir ces nœuds = casser le plus de chemins
                </span>
              </h2>
              {chokes.slice(0, 3).map((c, i) => (
                <div
                  key={c.asset}
                  style={{
                    padding: "0.7rem 0",
                    borderBottom:
                      i < Math.min(chokes.length, 3) - 1
                        ? "1px solid rgba(255,255,255,0.05)"
                        : "none",
                    fontSize: "0.85rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong>#{i + 1} {c.asset}</strong>
                    <span style={{ opacity: 0.7 }}>
                      casse <strong>{c.paths_through}</strong> chemins
                      {c.weighted_score > 0 && (
                        <> · score pondéré {c.weighted_score.toFixed(2)}</>
                      )}
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

        {/* Attack paths (G2) */}
        {paths.length > 0 && (
          <div style={{ marginTop: "1rem" }}>
            <NeuCard>
              <div style={{ padding: "1rem" }}>
                <h2
                  style={{
                    fontSize: "1rem",
                    marginBottom: "0.75rem",
                    display: "flex",
                    gap: 6,
                    alignItems: "center",
                  }}
                >
                  <AlertTriangle size={16} /> Chemins d&apos;attaque les plus probables
                  {lastRunAt && (
                    <span
                      style={{
                        marginLeft: "auto",
                        fontSize: "0.78rem",
                        opacity: 0.55,
                      }}
                    >
                      dernier calcul {new Date(lastRunAt).toLocaleString("fr-FR")}
                    </span>
                  )}
                </h2>
                {paths.map((p, i) => (
                  <div
                    key={`${p.src_asset}-${p.dst_asset}-${i}`}
                    style={{
                      padding: "0.7rem 0",
                      borderBottom:
                        i < paths.length - 1
                          ? "1px solid rgba(255,255,255,0.05)"
                          : "none",
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
          </div>
        )}
      </div>
    </PageShell>
  );
}

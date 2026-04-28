"use client";

// /enquetes — Phase G4a — list les Investigation Graphs en cours.
// Auto-refresh 10s. C'est l'onglet "L'IA bosse en ce moment" de la
// refonte UI.

import React, { useEffect, useState, useCallback } from "react";
import { PageShell } from "@/components/chrome/PageShell";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { Activity, RefreshCw, Brain } from "lucide-react";

interface GraphExecution {
  id: number;
  graph_name: string;
  asset_id: string | null;
  status: string;
  started_at: string;
  duration_ms: number | null;
  archive_reason: string | null;
  incident_id: number | null;
  error: string | null;
}

function fmtDuration(start: string, finished?: number | null): string {
  if (finished) {
    if (finished < 1000) return `${finished} ms`;
    if (finished < 60_000) return `${(finished / 1000).toFixed(1)} s`;
    return `${(finished / 60_000).toFixed(1)} min`;
  }
  const elapsed = Date.now() - new Date(start).getTime();
  if (elapsed < 60_000) return `${Math.floor(elapsed / 1000)} s`;
  return `${Math.floor(elapsed / 60_000)} min`;
}

export default function EnquetesPage() {
  const [executions, setExecutions] = useState<GraphExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const r = await fetch(
        "/api/tc/graph-executions?status=running&limit=50",
        { cache: "no-store" }
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setExecutions(d.executions || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  }, [load]);

  return (
    <PageShell
      title="Enquêtes en cours"
      subtitle="Les Investigation Graphs que l'IA traite actuellement"
      right={
        <ChromeButton onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
        </ChromeButton>
      }
    >
      <div style={{ padding: "1rem 0" }}>
        {error && <ErrorBanner message={error} />}

        {executions.length === 0 ? (
          <NeuCard>
            <div style={{ padding: "2rem", textAlign: "center" }}>
              <Brain size={48} style={{ opacity: 0.4, margin: "0 auto 1rem" }} />
              <h3 style={{ marginBottom: "0.5rem" }}>Aucune enquête en cours</h3>
              <p style={{ opacity: 0.7 }}>
                Les graphs déterministes tranchent la majorité des cas en
                quelques millisecondes — il est normal que cette page reste
                souvent vide.
              </p>
            </div>
          </NeuCard>
        ) : (
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
                <Activity size={16} /> {executions.length} enquête{executions.length > 1 ? "s" : ""} actuellement en cours
              </h2>
              {executions.map((ex) => (
                <div
                  key={ex.id}
                  style={{
                    padding: "0.7rem 0",
                    borderBottom: "1px solid rgba(255,255,255,0.05)",
                    fontSize: "0.85rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong>{ex.graph_name}</strong>
                    <span style={{ opacity: 0.7, fontSize: "0.78rem" }}>
                      en cours depuis {fmtDuration(ex.started_at)}
                    </span>
                  </div>
                  <div style={{ opacity: 0.65, fontSize: "0.78rem", marginTop: "0.2rem" }}>
                    {ex.asset_id ? `asset : ${ex.asset_id}` : "asset non résolu"}
                    {" · "}id #{ex.id}
                  </div>
                </div>
              ))}
            </div>
          </NeuCard>
        )}
      </div>
    </PageShell>
  );
}

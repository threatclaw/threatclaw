"use client";

// /archives — Phase G4a — outil forensique : tout ce qui a été clos
// (auto-archive par graph, FP IA, résolu par firewall, etc.) avec
// filtres.

import React, { useEffect, useState, useCallback } from "react";
import { PageShell } from "@/components/chrome/PageShell";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { Archive, RefreshCw, Filter } from "lucide-react";

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

const KNOWN_REASONS = [
  { value: "", label: "Tous les motifs" },
  { value: "resolu par firewall", label: "Résolu par firewall" },
  { value: "non corrobore - asset isolee", label: "Non corroboré (asset isolé)" },
  { value: "bruit Internet — sondes UDP amplification bloquees", label: "Bruit Internet" },
  { value: "shadow AI detecte — revue hebdo compliance, pas une attaque", label: "Shadow AI compliance" },
  { value: "echec d'auth admin isole — probable typo", label: "Auth admin isolée (typo)" },
];

const STATUS_OPTIONS = [
  { value: "archived", label: "Archives auto" },
  { value: "inconclusive", label: "Inconcluant" },
  { value: "incident", label: "Promus en incident" },
  { value: "failed", label: "Échec d'exécution" },
];

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function ArchivesPage() {
  const [executions, setExecutions] = useState<GraphExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Default = "" (tous les statuts terminaux). En G1 les graphs rendent
  // souvent un verdict 'incident' instantanément — restreindre à
  // 'archived' par défaut cachait toutes les décisions à fort enjeu.
  const [statusFilter, setStatusFilter] = useState("");
  const [reasonFilter, setReasonFilter] = useState("");
  const [assetFilter, setAssetFilter] = useState("");
  const [sinceFilter, setSinceFilter] = useState("168"); // 7 jours

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      // Status vide = tous les statuts terminaux (incident + archived +
      // inconclusive + failed). Ne pas envoyer le param dans ce cas
      // sinon le backend l'utilise comme `status = ''` et matche 0 row.
      if (statusFilter) params.set("status", statusFilter);
      params.set("limit", "100");
      if (reasonFilter) params.set("archive_reason", reasonFilter);
      if (assetFilter) params.set("asset_id", assetFilter);
      if (sinceFilter) params.set("since_hours", sinceFilter);

      const r = await fetch(`/api/tc/graph-executions?${params.toString()}`, {
        cache: "no-store",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setExecutions(d.executions || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, reasonFilter, assetFilter, sinceFilter]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <PageShell
      title="Archives"
      subtitle="Outil forensique — tout ce qui a été clos (auto + manuel)"
      right={
        <ChromeButton onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
        </ChromeButton>
      }
    >
      <div style={{ padding: "1rem 0" }}>
        {error && <ErrorBanner message={error} />}

        {/* Filtres */}
        <NeuCard>
          <div style={{ padding: "1rem" }}>
            <h3
              style={{
                fontSize: "0.95rem",
                marginBottom: "0.75rem",
                display: "flex",
                gap: 6,
                alignItems: "center",
              }}
            >
              <Filter size={14} /> Filtres
            </h3>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: "0.75rem",
                fontSize: "0.85rem",
              }}
            >
              <div>
                <div style={{ fontSize: "0.78rem", opacity: 0.7, marginBottom: "0.25rem" }}>
                  Statut
                </div>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.4rem",
                    background: "rgba(255,255,255,0.05)",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 4,
                    color: "inherit",
                    fontSize: "0.85rem",
                  }}
                >
                  {STATUS_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <div style={{ fontSize: "0.78rem", opacity: 0.7, marginBottom: "0.25rem" }}>
                  Motif
                </div>
                <select
                  value={reasonFilter}
                  onChange={(e) => setReasonFilter(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.4rem",
                    background: "rgba(255,255,255,0.05)",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 4,
                    color: "inherit",
                    fontSize: "0.85rem",
                  }}
                >
                  {KNOWN_REASONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <div style={{ fontSize: "0.78rem", opacity: 0.7, marginBottom: "0.25rem" }}>
                  Asset (substring)
                </div>
                <input
                  type="text"
                  value={assetFilter}
                  onChange={(e) => setAssetFilter(e.target.value)}
                  placeholder="srv-01-dom"
                  style={{
                    width: "100%",
                    padding: "0.4rem",
                    background: "rgba(255,255,255,0.05)",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 4,
                    color: "inherit",
                    fontSize: "0.85rem",
                  }}
                />
              </div>
              <div>
                <div style={{ fontSize: "0.78rem", opacity: 0.7, marginBottom: "0.25rem" }}>
                  Période
                </div>
                <select
                  value={sinceFilter}
                  onChange={(e) => setSinceFilter(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.4rem",
                    background: "rgba(255,255,255,0.05)",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 4,
                    color: "inherit",
                    fontSize: "0.85rem",
                  }}
                >
                  <option value="24">Dernières 24 h</option>
                  <option value="168">Derniers 7 jours</option>
                  <option value="720">Derniers 30 jours</option>
                  <option value="">Tout</option>
                </select>
              </div>
            </div>
          </div>
        </NeuCard>

        {/* Liste */}
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
                <Archive size={16} /> {executions.length} enregistrement{executions.length > 1 ? "s" : ""}
              </h2>
              {executions.length === 0 ? (
                <p style={{ opacity: 0.6, fontSize: "0.9rem", padding: "1rem 0" }}>
                  Aucun enregistrement avec ces filtres.
                </p>
              ) : (
                executions.map((ex, i) => (
                  <div
                    key={ex.id}
                    style={{
                      padding: "0.5rem 0",
                      borderBottom:
                        i < executions.length - 1
                          ? "1px solid rgba(255,255,255,0.05)"
                          : "none",
                      fontSize: "0.85rem",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <strong>{ex.graph_name}</strong>
                      <span style={{ opacity: 0.7, fontSize: "0.78rem" }}>
                        {fmtDate(ex.started_at)}
                      </span>
                    </div>
                    <div style={{ opacity: 0.65, fontSize: "0.78rem", marginTop: "0.2rem" }}>
                      {ex.asset_id || "asset non résolu"}
                      {" · "}
                      {ex.archive_reason ? `motif : ${ex.archive_reason}` : ex.status}
                      {ex.duration_ms ? ` · ${ex.duration_ms} ms` : ""}
                      {ex.incident_id ? ` · → incident #${ex.incident_id}` : ""}
                    </div>
                  </div>
                ))
              )}
            </div>
          </NeuCard>
        </div>
      </div>
    </PageShell>
  );
}

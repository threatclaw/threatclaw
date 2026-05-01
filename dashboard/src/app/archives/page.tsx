"use client";

import React, { useEffect, useState, useCallback } from "react";
import { PageShell } from "@/components/chrome/PageShell";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { Archive, RefreshCw, Search, X } from "lucide-react";

interface Incident {
  id: number;
  asset: string;
  title: string;
  summary: string | null;
  verdict: string;
  confidence: number | null;
  severity: string | null;
  alert_count: number | null;
  status: string;
  created_at: string;
  updated_at: string;
}

const severityColor: Record<string, string> = {
  CRITICAL: "#ff2020", HIGH: "#ff6030", MEDIUM: "#e0a020", LOW: "#30a050",
};

const verdictStyle: Record<string, { color: string; label: string }> = {
  inconclusive: { color: "#e0a020", label: "Inconclusif" },
  false_positive: { color: "#30a050", label: "Faux positif" },
};

function splitTitle(raw: string | null): string {
  if (!raw) return "";
  const sep = raw.indexOf(" — ") >= 0 ? " — " : (raw.indexOf(" - ") >= 0 ? " - " : null);
  if (!sep) return raw;
  return raw.substring(0, raw.indexOf(sep)).trim();
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function ArchivesPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<"" | "inconclusive" | "false_positive">("");
  const [sinceHours, setSinceHours] = useState(168);
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      // Fetch both non-archived and archived incidents so manually archived
      // inconclusive/FP incidents are also visible.
      const [r1, r2] = await Promise.all([
        fetch("/api/tc/incidents", { cache: "no-store" }),
        fetch("/api/tc/incidents?status=archived", { cache: "no-store" }),
      ]);
      const [d1, d2] = await Promise.all([r1.json(), r2.json()]);
      const all = [...(d1.incidents || []), ...(d2.incidents || [])];
      const seen = new Set<number>();
      const unique = all.filter(inc => { if (seen.has(inc.id)) return false; seen.add(inc.id); return true; });
      const cutoff = sinceHours > 0 ? Date.now() - sinceHours * 3600 * 1000 : 0;
      setIncidents(unique.filter((inc: Incident) => {
        const isArchiveVerdict = inc.verdict === "inconclusive" || inc.verdict === "false_positive";
        const inPeriod = cutoff === 0 || new Date(inc.created_at).getTime() >= cutoff;
        return isArchiveVerdict && inPeriod;
      }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, [sinceHours]);

  useEffect(() => { load(); }, [load]);

  const filtered = incidents.filter(inc => {
    if (verdictFilter && inc.verdict !== verdictFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return inc.title.toLowerCase().includes(q) || inc.asset.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <PageShell
      title="Archives"
      subtitle="Incidents classés non conclusifs ou faux positifs"
      right={
        <ChromeButton onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
        </ChromeButton>
      }
    >
      <style>{`
        .arch-filters { display: flex; align-items: center; gap: 8px; padding: 10px 0 12px; border-bottom: 1px solid var(--tc-border); flex-wrap: wrap; }
        .arch-search { display: flex; align-items: center; gap: 6px; background: var(--tc-input); border: 1px solid var(--tc-border); padding: 4px 10px; height: 28px; }
        .arch-search input { background: none; border: none; outline: none; color: var(--tc-text); font-size: 11px; font-family: ui-monospace, 'JetBrains Mono', monospace; width: 180px; }
        .arch-filter-btn { font-size: 9px; font-weight: 700; padding: 4px 10px; font-family: ui-monospace, 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: 0.05em; border: 1px solid var(--tc-border); background: var(--tc-surface-alt); color: var(--tc-text-muted); cursor: pointer; }
        .arch-filter-btn.active-amber { border-color: rgba(224,160,32,0.4); background: rgba(224,160,32,0.08); color: #e0a020; }
        .arch-filter-btn.active-green { border-color: rgba(48,160,80,0.4); background: rgba(48,160,80,0.08); color: #30a050; }
        .arch-select { font-size: 10px; padding: 4px 8px; background: var(--tc-input); border: 1px solid var(--tc-border); color: var(--tc-text); font-family: ui-monospace, 'JetBrains Mono', monospace; cursor: pointer; }
        .arch-table-head { display: grid; grid-template-columns: 70px 48px 120px 1fr 130px 80px; gap: 0; padding: 6px 14px; background: var(--tc-surface-alt); border: 1px solid var(--tc-border); border-bottom: none; font-size: 9px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-family: ui-monospace, 'JetBrains Mono', monospace; color: var(--tc-text-muted); }
        .arch-row { border: 1px solid var(--tc-border); border-top: none; background: var(--tc-surface); }
        .arch-grid { display: grid; grid-template-columns: 70px 48px 120px 1fr 130px 80px; gap: 0; padding: 10px 14px; align-items: center; }
        .arch-sev { font-size: 9px; font-weight: 700; padding: 2px 7px; text-transform: uppercase; font-family: ui-monospace, 'JetBrains Mono', monospace; border: 1px solid; letter-spacing: 0.05em; }
        .arch-id { font-size: 12px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; }
        .arch-verdict { font-size: 9px; font-weight: 700; padding: 2px 7px; font-family: ui-monospace, 'JetBrains Mono', monospace; border: 1px solid; letter-spacing: 0.04em; text-transform: uppercase; }
        .arch-title { font-size: 12px; font-weight: 600; color: var(--tc-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .arch-sub { display: flex; gap: 6px; align-items: center; font-size: 10px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; margin-top: 2px; }
        .arch-sub .ip { color: var(--tc-blue); }
        .arch-date { font-size: 10px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; }
        .arch-conf { font-size: 10px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; }
        .arch-summary { padding: 0 14px 10px; padding-top: 8px; font-size: 11px; color: var(--tc-text-muted); line-height: 1.5; border-top: 1px solid var(--tc-border); }
        .arch-empty { text-align: center; padding: 48px 20px; background: var(--tc-surface); border: 1px solid var(--tc-border); }
      `}</style>

      {error && <ErrorBanner message={error} />}

      <div className="arch-filters">
        <div className="arch-search">
          <Search size={11} color="var(--tc-text-muted)" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher asset ou titre..."
          />
          {search && (
            <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
              <X size={11} color="var(--tc-text-muted)" />
            </button>
          )}
        </div>
        <button
          className={`arch-filter-btn${verdictFilter === "inconclusive" ? " active-amber" : ""}`}
          onClick={() => setVerdictFilter(verdictFilter === "inconclusive" ? "" : "inconclusive")}
        >
          Inconclusif
        </button>
        <button
          className={`arch-filter-btn${verdictFilter === "false_positive" ? " active-green" : ""}`}
          onClick={() => setVerdictFilter(verdictFilter === "false_positive" ? "" : "false_positive")}
        >
          Faux positif
        </button>
        <select
          className="arch-select"
          value={sinceHours}
          onChange={e => setSinceHours(Number(e.target.value))}
        >
          <option value={24}>Dernières 24 h</option>
          <option value={168}>Derniers 7 jours</option>
          <option value={720}>Derniers 30 jours</option>
          <option value={0}>Tout</option>
        </select>
        <span style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace", marginLeft: "auto" }}>
          {loading ? "..." : `${filtered.length} enregistrement${filtered.length !== 1 ? "s" : ""}`}
        </span>
      </div>

      {!loading && filtered.length === 0 && (
        <div className="arch-empty">
          <Archive size={32} style={{ color: "var(--tc-text-muted)", margin: "0 auto 10px", display: "block" }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--tc-text)", marginBottom: 4 }}>
            Aucun enregistrement
          </div>
          <div style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
            Aucun incident inconclusif ou faux positif sur la période sélectionnée.
          </div>
        </div>
      )}

      {!loading && filtered.length > 0 && (
        <>
          <div className="arch-table-head">
            <span>Severite</span>
            <span>ID</span>
            <span>Verdict</span>
            <span>Signal</span>
            <span>Date</span>
            <span>Confiance</span>
          </div>
          <div>
            {filtered.map(inc => {
              const sevColor = severityColor[inc.severity || "MEDIUM"] || "#888";
              const vStyle = verdictStyle[inc.verdict] || { color: "#888", label: inc.verdict };
              const title = splitTitle(inc.title) || inc.title;
              return (
                <div key={inc.id} className="arch-row">
                  <div className="arch-grid">
                    <div>
                      <span className="arch-sev" style={{ background: sevColor + "22", color: sevColor, borderColor: sevColor + "55" }}>
                        {inc.severity || "—"}
                      </span>
                    </div>
                    <div className="arch-id">#{inc.id}</div>
                    <div>
                      <span className="arch-verdict" style={{ background: vStyle.color + "22", color: vStyle.color, borderColor: vStyle.color + "55" }}>
                        {vStyle.label}
                      </span>
                    </div>
                    <div style={{ minWidth: 0 }}>
                      <div className="arch-title">{title}</div>
                      <div className="arch-sub">
                        <span className="ip">{inc.asset}</span>
                        <span>·</span>
                        <span>{inc.alert_count || 0} alerts</span>
                      </div>
                    </div>
                    <div className="arch-date">{fmtDate(inc.created_at)}</div>
                    <div className="arch-conf">
                      {inc.confidence != null ? `${Math.round(inc.confidence * 100)} %` : "—"}
                    </div>
                  </div>
                  {inc.summary && (
                    <div className="arch-summary">
                      {inc.summary.length > 220 ? inc.summary.substring(0, 220) + "..." : inc.summary}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </PageShell>
  );
}

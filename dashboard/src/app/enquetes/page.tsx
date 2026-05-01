"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { PageShell } from "@/components/chrome/PageShell";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { Brain, RefreshCw, FileText, Clock, Search, X } from "lucide-react";

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

function splitTitle(raw: string | null): string {
  if (!raw) return "";
  const sep = raw.indexOf(" — ") >= 0 ? " — " : (raw.indexOf(" - ") >= 0 ? " - " : null);
  if (!sep) return raw;
  return raw.substring(0, raw.indexOf(sep)).trim();
}

function getTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "a l'instant";
  if (mins < 60) return `il y a ${mins} min`;
  const h = Math.floor(mins / 60);
  if (h < 24) return `il y a ${h} h`;
  return `il y a ${Math.floor(h / 24)} j`;
}

export default function EnquetesPage() {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      const r = await fetch("/api/tc/incidents", { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setIncidents((d.incidents || []).filter((inc: Incident) => inc.verdict === "pending"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  }, [load]);

  const reinvestigate = async (id: number) => {
    try {
      await fetch(`/api/tc/incidents/${id}/reinvestigate`, { method: "POST" });
      setTimeout(load, 2000);
    } catch {}
  };

  const filtered = search
    ? incidents.filter(inc =>
        inc.title.toLowerCase().includes(search.toLowerCase()) ||
        inc.asset.toLowerCase().includes(search.toLowerCase())
      )
    : incidents;

  return (
    <PageShell
      title="Enquêtes en cours"
      subtitle="Cas ambigus en attente de verdict — investigation IA active ou en attente de relance"
      right={
        <ChromeButton onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
        </ChromeButton>
      }
    >
      <style>{`
        .enq-toolbar { display: flex; align-items: center; gap: 8px; padding: 8px 0 12px; border-bottom: 1px solid var(--tc-border); margin-bottom: 0; }
        .enq-search { display: flex; align-items: center; gap: 6px; background: var(--tc-input); border: 1px solid var(--tc-border); padding: 4px 10px; height: 28px; }
        .enq-search input { background: none; border: none; outline: none; color: var(--tc-text); font-size: 11px; font-family: ui-monospace, 'JetBrains Mono', monospace; width: 180px; }
        .enq-table-head { display: grid; grid-template-columns: 70px 48px 1fr 150px 100px 150px; gap: 0; padding: 6px 14px; background: var(--tc-surface-alt); border: 1px solid var(--tc-border); border-bottom: none; font-size: 9px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-family: ui-monospace, 'JetBrains Mono', monospace; color: var(--tc-text-muted); }
        .enq-row { border: 1px solid var(--tc-border); border-top: none; background: var(--tc-surface); }
        .enq-grid { display: grid; grid-template-columns: 70px 48px 1fr 150px 100px 150px; gap: 0; padding: 10px 14px; align-items: center; }
        .enq-sev { font-size: 9px; font-weight: 700; padding: 2px 7px; text-transform: uppercase; font-family: ui-monospace, 'JetBrains Mono', monospace; border: 1px solid; letter-spacing: 0.05em; }
        .enq-id { font-size: 12px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; }
        .enq-title { font-size: 12px; font-weight: 600; color: var(--tc-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .enq-sub { display: flex; gap: 6px; align-items: center; font-size: 10px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; margin-top: 2px; }
        .enq-sub .ip { color: var(--tc-blue); }
        .enq-status { font-size: 10px; font-weight: 700; color: #e0a020; font-family: ui-monospace, 'JetBrains Mono', monospace; display: flex; align-items: center; gap: 5px; }
        .enq-when { font-size: 10px; color: var(--tc-text-muted); font-family: ui-monospace, 'JetBrains Mono', monospace; }
        .enq-actions { display: flex; gap: 4px; }
        .enq-btn { font-size: 9px; font-weight: 700; padding: 3px 8px; font-family: ui-monospace, 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: 0.04em; border: 1px solid var(--tc-border); background: var(--tc-surface-alt); color: var(--tc-text-muted); cursor: pointer; display: inline-flex; align-items: center; gap: 4px; }
        .enq-btn:hover { color: var(--tc-text); border-color: var(--tc-text-muted); }
        .enq-empty { text-align: center; padding: 48px 20px; background: var(--tc-surface); border: 1px solid var(--tc-border); margin-top: 0; }
      `}</style>

      {error && <ErrorBanner message={error} />}

      <div className="enq-toolbar">
        <div className="enq-search">
          <Search size={11} color="var(--tc-text-muted)" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher..."
          />
          {search && (
            <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
              <X size={11} color="var(--tc-text-muted)" />
            </button>
          )}
        </div>
        <span style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace", marginLeft: "auto" }}>
          {loading ? "..." : `${incidents.length} enquête${incidents.length !== 1 ? "s" : ""} en cours`}
          {" · "}rafraîchissement auto 10 s
        </span>
      </div>

      {!loading && filtered.length === 0 && (
        <div className="enq-empty">
          <Brain size={32} style={{ color: "var(--tc-text-muted)", margin: "0 auto 10px", display: "block" }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--tc-text)", marginBottom: 4 }}>
            Aucune enquête en cours
          </div>
          <div style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
            Les cas ambigus routés par les Investigation Graphs apparaissent ici le temps que l'IA rende son verdict.
          </div>
        </div>
      )}

      {!loading && filtered.length > 0 && (
        <>
          <div className="enq-table-head">
            <span>Severite</span>
            <span>ID</span>
            <span>Signal</span>
            <span>Statut</span>
            <span>Detecte</span>
            <span>Actions</span>
          </div>
          <div>
            {filtered.map(inc => {
              const sevColor = severityColor[inc.severity || "MEDIUM"] || "#888";
              const title = splitTitle(inc.title) || inc.title;
              return (
                <div key={inc.id} className="enq-row">
                  <div className="enq-grid">
                    <div>
                      <span className="enq-sev" style={{ background: sevColor + "22", color: sevColor, borderColor: sevColor + "55" }}>
                        {inc.severity || "—"}
                      </span>
                    </div>
                    <div className="enq-id">#{inc.id}</div>
                    <div style={{ minWidth: 0 }}>
                      <div className="enq-title">{title}</div>
                      <div className="enq-sub">
                        <span className="ip">{inc.asset}</span>
                        <span>·</span>
                        <span>{inc.alert_count || 0} alerts</span>
                      </div>
                    </div>
                    <div className="enq-status">
                      <Clock size={10} />
                      Investigation en cours
                    </div>
                    <div className="enq-when">{getTimeAgo(inc.created_at)}</div>
                    <div className="enq-actions">
                      <button
                        className="enq-btn"
                        onClick={() => reinvestigate(inc.id)}
                        title="Relancer l'investigation IA"
                      >
                        <Brain size={9} /> Relancer
                      </button>
                      <button
                        className="enq-btn"
                        onClick={() => router.push(`/investigate/${inc.id}`)}
                        title="Ouvrir le dossier d'investigation"
                      >
                        <FileText size={9} /> Rapport
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </PageShell>
  );
}

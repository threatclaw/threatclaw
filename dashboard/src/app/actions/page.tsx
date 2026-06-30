"use client";

// Actions prioritaires — the RSSI's ordered remediation to-do list. V1 = the
// most-exposed assets to patch first, driven by the per-asset exposure score
// (Grype × KEV × EPSS × criticality × network exposure). Data: GET
// /api/tc/priority-actions (see src/enrichment/exposure_score.rs).

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useLocale } from "@/lib/useLocale";
import { PageShell } from "@/components/chrome/PageShell";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { fetchPriorityActions, type PriorityAction } from "@/lib/tc-api";
import { t as tr } from "@/lib/i18n";
import {
  ListChecks,
  RefreshCw,
  Wrench,
  Flame,
  Globe,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
} from "lucide-react";

const SEV: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: "#e84040", bg: "rgba(232,64,64,0.08)", border: "rgba(232,64,64,0.25)" },
  HIGH: { color: "#d07020", bg: "rgba(208,112,32,0.08)", border: "rgba(208,112,32,0.25)" },
  MEDIUM: { color: "var(--tc-amber)", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.25)" },
  LOW: { color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.25)" },
};

function sev(severity: string) {
  return SEV[severity?.toUpperCase()] ?? SEV.LOW;
}

export default function PriorityActionsPage() {
  const locale = useLocale();
  const fr = locale === "fr";
  const [actions, setActions] = useState<PriorityAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetchPriorityActions({ min_score: 40, limit: 100 });
      setActions(res.actions);
      setError(null);
    } catch {
      setError(tr("backendNotAccessible", locale));
    }
    setLoading(false);
  }, [locale]);

  useEffect(() => {
    load();
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <PageShell
      title={fr ? "Actions prioritaires" : "Priority actions"}
      subtitle={
        fr
          ? "À traiter en premier — les assets les plus exposés, classés par risque (vulnérabilité × exploitation active × exposition réseau)."
          : "Handle these first — the most exposed assets, ranked by risk (vulnerability × active exploitation × network exposure)."
      }
      right={
        <ChromeButton onClick={load}>
          <RefreshCw size={14} /> {fr ? "Rafraîchir" : "Refresh"}
        </ChromeButton>
      }
    >
      {error && <ErrorBanner message={error} />}

      {!loading && actions.length === 0 && !error && (
        <NeuCard>
          <div style={{ display: "flex", alignItems: "center", gap: 12, padding: 24, color: "var(--tc-text-muted)" }}>
            <ShieldCheck size={22} color="var(--tc-green)" />
            <div>
              <div style={{ fontWeight: 600, color: "var(--tc-text)" }}>
                {fr ? "Aucune action prioritaire" : "No priority action"}
              </div>
              <div style={{ fontSize: 13 }}>
                {fr
                  ? "Aucun asset à risque détecté. Les expositions apparaissent ici après le scan de vulnérabilités."
                  : "No at-risk asset detected. Exposures appear here after the vulnerability scan."}
              </div>
            </div>
          </div>
        </NeuCard>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {actions.map((a, i) => {
          const c = sev(a.severity);
          const open = expanded === a.asset_id;
          return (
            <NeuCard key={a.asset_id}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 14, padding: "14px 16px" }}>
                {/* Rank */}
                <div
                  style={{
                    flex: "0 0 auto",
                    width: 30,
                    height: 30,
                    borderRadius: 8,
                    display: "grid",
                    placeItems: "center",
                    fontWeight: 700,
                    fontSize: 14,
                    color: c.color,
                    background: c.bg,
                    border: `1px solid ${c.border}`,
                  }}
                >
                  {i + 1}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  {/* Asset + score */}
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                    <Link
                      href={`/assets/${encodeURIComponent(a.asset_id)}`}
                      style={{ fontWeight: 600, color: "var(--tc-text)", textDecoration: "none" }}
                    >
                      {a.asset_name}
                    </Link>
                    <span
                      style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: c.color,
                        background: c.bg,
                        border: `1px solid ${c.border}`,
                        borderRadius: 6,
                        padding: "1px 7px",
                      }}
                    >
                      {a.score}/100 · {a.severity}
                    </span>
                    {a.in_kev && (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: "#e84040" }}>
                        <Flame size={12} /> {fr ? "exploité activement" : "actively exploited"}
                      </span>
                    )}
                    {a.exposed && (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--tc-amber)" }}>
                        <Globe size={12} /> {fr ? "exposé Internet" : "internet-facing"}
                      </span>
                    )}
                  </div>

                  {/* The action */}
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6, fontSize: 13.5 }}>
                    <Wrench size={14} color="var(--tc-text-muted)" style={{ flex: "0 0 auto" }} />
                    <span style={{ color: "var(--tc-text)" }}>{a.summary}</span>
                  </div>

                  {/* Breakdown toggle */}
                  {a.breakdown.length > 0 && (
                    <button
                      onClick={() => setExpanded(open ? null : a.asset_id)}
                      style={{
                        marginTop: 8,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 4,
                        fontSize: 12,
                        color: "var(--tc-text-muted)",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        padding: 0,
                      }}
                    >
                      {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      {fr ? "Pourquoi" : "Why"}
                    </button>
                  )}
                  {open && (
                    <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12.5, color: "var(--tc-text-muted)" }}>
                      {a.breakdown.map((b, k) => (
                        <li key={k}>{b}</li>
                      ))}
                    </ul>
                  )}
                </div>

                <ListChecks size={16} color="var(--tc-text-muted)" style={{ flex: "0 0 auto", marginTop: 4 }} />
              </div>
            </NeuCard>
          );
        })}
      </div>
    </PageShell>
  );
}

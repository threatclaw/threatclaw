"use client";

import React, { useEffect, useState } from "react";
import { useLocale } from "@/lib/useLocale";
import Link from "next/link";

// Phase G acceptance dashboard. Lives during the validation period
// (between Sprint 6 ship and v1.1.0 tag). Surfaces the single criterion
// that gates Phase G shipping: zero incidents in the last 7 days with
// `proposed_actions.actions` empty/null. Auto-refreshes every 30s.

interface Acceptance {
  lookback_days: number;
  incidents_total: number;
  incidents_missing_actions: number;
  actionable_ratio: number | null;
  missing_ids: number[];
  verdict: "ready" | "not_ready" | "no_data";
  computed_at: string;
  error?: string;
}

const REFRESH_MS = 30_000;

export default function PhaseGPage() {
  const { locale } = useLocale();
  const fr = locale === "fr";

  const [data, setData] = useState<Acceptance | null>(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(7);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  async function fetchData(d: number) {
    try {
      const res = await fetch(`/api/tc/admin/phase-g-acceptance?days=${d}`);
      const j = (await res.json()) as Acceptance;
      setData(j);
      setLastFetch(new Date());
    } catch (e: any) {
      setData({
        lookback_days: d,
        incidents_total: 0,
        incidents_missing_actions: 0,
        actionable_ratio: null,
        missing_ids: [],
        verdict: "no_data",
        computed_at: new Date().toISOString(),
        error: String(e?.message || e),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchData(days);
    const iv = setInterval(() => fetchData(days), REFRESH_MS);
    return () => clearInterval(iv);
  }, [days]);

  const badge = (() => {
    if (!data || loading) {
      return { color: "var(--tc-text-muted)", label: fr ? "Chargement…" : "Loading…" };
    }
    if (data.error) {
      return { color: "#e04040", label: fr ? "Erreur" : "Error" };
    }
    switch (data.verdict) {
      case "ready":
        return { color: "#30a050", label: fr ? "PRÊT" : "READY" };
      case "not_ready":
        return { color: "#e04040", label: fr ? "NON PRÊT" : "NOT READY" };
      case "no_data":
        return { color: "#888", label: fr ? "Pas de données" : "No data" };
    }
  })();

  const ratioPct =
    data && data.actionable_ratio != null ? Math.round(data.actionable_ratio * 1000) / 10 : null;

  // Gauge color thresholds — green > 95 %, amber 80-95, red < 80.
  const gaugeColor =
    ratioPct == null
      ? "#888"
      : ratioPct >= 95
        ? "#30a050"
        : ratioPct >= 80
          ? "#d09020"
          : "#e04040";

  return (
    <div
      style={{
        padding: "24px 28px",
        color: "var(--tc-text)",
        fontFamily: "'JetBrains Mono', ui-monospace, monospace",
        maxWidth: "1100px",
        margin: "0 auto",
      }}
    >
      <div style={{ marginBottom: "20px" }}>
        <h1 style={{ fontSize: "16px", fontWeight: 800, marginBottom: "4px" }}>
          {fr ? "Phase G — readiness" : "Phase G — readiness"}
        </h1>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
          {fr
            ? "Critère shipping Phase G : 0 incident sur 7 jours sans action HITL proposée. Critère figé dans PHASE_G_INVESTIGATION_GRAPHS.md."
            : "Phase G shipping criterion: zero incidents over 7 days with no proposed HITL action. Defined in PHASE_G_INVESTIGATION_GRAPHS.md."}
        </div>
      </div>

      {/* ── Main gauge ── */}
      <div
        style={{
          background: "var(--tc-bg)",
          border: `1px solid ${badge.color}`,
          borderRadius: "var(--tc-radius-md)",
          padding: "20px 24px",
          marginBottom: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "baseline", gap: "16px", marginBottom: "12px" }}>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            {fr ? "Statut" : "Status"}
          </div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 800,
              color: badge.color,
              padding: "3px 10px",
              borderRadius: "3px",
              background: `${badge.color}15`,
              border: `1px solid ${badge.color}40`,
            }}
          >
            {badge.label}
          </div>
          {data && data.verdict !== "no_data" && (
            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
              {fr
                ? `Fenêtre ${data.lookback_days}j — ${data.incidents_total} incidents`
                : `${data.lookback_days}d window — ${data.incidents_total} incidents`}
            </div>
          )}
        </div>

        {ratioPct != null && (
          <>
            <div
              style={{
                display: "flex",
                alignItems: "baseline",
                gap: "8px",
                marginBottom: "8px",
              }}
            >
              <span style={{ fontSize: "32px", fontWeight: 800, color: gaugeColor, fontFamily: "inherit" }}>
                {ratioPct.toFixed(1)}%
              </span>
              <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
                {fr ? "incidents avec action proposée" : "incidents with proposed action"}
              </span>
            </div>

            {/* Gauge bar */}
            <div
              style={{
                height: "10px",
                background: "var(--tc-input)",
                borderRadius: "5px",
                overflow: "hidden",
                border: "1px solid var(--tc-border)",
                marginBottom: "12px",
              }}
            >
              <div
                style={{
                  width: `${Math.max(0, Math.min(100, ratioPct))}%`,
                  height: "100%",
                  background: gaugeColor,
                  transition: "width 600ms ease, background 200ms",
                }}
              />
            </div>

            {/* Threshold ticks */}
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "8px" }}>
              <span>0%</span>
              <span style={{ color: "#e04040" }}>80% (alerte)</span>
              <span style={{ color: "#d09020" }}>95% (ok)</span>
              <span>100%</span>
            </div>
          </>
        )}

        {data && data.incidents_missing_actions > 0 && (
          <div
            style={{
              marginTop: "12px",
              padding: "8px 10px",
              background: "rgba(224,64,64,0.06)",
              border: "1px solid rgba(224,64,64,0.25)",
              borderRadius: "var(--tc-radius-sm)",
              fontSize: "11px",
              color: "var(--tc-text-sec)",
            }}
          >
            <div style={{ marginBottom: "4px" }}>
              <strong style={{ color: "#e04040" }}>
                {data.incidents_missing_actions}{" "}
                {fr ? "incident(s) sans action HITL :" : "incident(s) missing HITL action:"}
              </strong>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
              {data.missing_ids.map((id) => (
                <Link
                  key={id}
                  href={`/incidents?id=${id}`}
                  style={{
                    fontFamily: "monospace",
                    fontSize: "10px",
                    padding: "1px 6px",
                    background: "var(--tc-input)",
                    border: "1px solid var(--tc-border)",
                    borderRadius: "3px",
                    color: "var(--tc-blue)",
                    textDecoration: "none",
                  }}
                >
                  #{id}
                </Link>
              ))}
            </div>
            <div style={{ marginTop: "8px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
              {fr
                ? "→ ces incidents devraient avoir au moins 1 bouton dans le bloc « Que faire maintenant ». Si vide, vérifier (1) le verdict ReAct (a-t-il proposé des actions ?), (2) le fallback rules-based dans /incidents (block_ip, isolate_host…)."
                : "→ each of these should display at least one button in the 'What to do now' block. If empty, verify (1) the ReAct verdict (did it propose actions?), (2) the rules-based fallback in /incidents (block_ip, isolate_host…)."}
            </div>
          </div>
        )}

        {data && data.error && (
          <div
            style={{
              marginTop: "12px",
              padding: "8px 10px",
              background: "rgba(224,64,64,0.08)",
              border: "1px solid rgba(224,64,64,0.3)",
              borderRadius: "var(--tc-radius-sm)",
              fontSize: "11px",
              color: "#e04040",
            }}
          >
            {data.error}
          </div>
        )}
      </div>

      {/* ── Window selector + last fetch ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "16px",
          fontSize: "10px",
          color: "var(--tc-text-muted)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <span>{fr ? "Fenêtre :" : "Window:"}</span>
          {[1, 3, 7, 14, 30].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              style={{
                padding: "3px 8px",
                fontSize: "10px",
                fontFamily: "inherit",
                border: "1px solid var(--tc-border)",
                background: days === d ? "var(--tc-blue)" : "var(--tc-input)",
                color: days === d ? "#fff" : "var(--tc-text)",
                borderRadius: "3px",
                cursor: "pointer",
              }}
            >
              {d}j
            </button>
          ))}
        </div>
        <div style={{ marginLeft: "auto" }}>
          {lastFetch ? (
            <>
              {fr ? "Dernier check :" : "Last check:"} {lastFetch.toLocaleTimeString()} —{" "}
              {fr ? "auto-refresh 30s" : "auto-refresh 30s"}
            </>
          ) : (
            <span>—</span>
          )}
        </div>
      </div>

      {/* ── Acceptance criteria reminder ── */}
      <div
        style={{
          marginTop: "24px",
          padding: "12px 16px",
          background: "var(--tc-bg)",
          border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-sm)",
        }}
      >
        <div style={{ fontSize: "11px", fontWeight: 700, marginBottom: "8px", color: "var(--tc-text-sec)" }}>
          {fr ? "Critères Phase G complets (PHASE_G_INVESTIGATION_GRAPHS.md)" : "Full Phase G acceptance criteria"}
        </div>
        <ul style={{ paddingLeft: "20px", fontSize: "10px", color: "var(--tc-text-muted)", lineHeight: 1.6 }}>
          <li>
            {fr
              ? "Aucun incident « Aucune action HITL proposée » sur 7 jours consécutifs"
              : "Zero incidents with no proposed HITL action over 7 consecutive days"}{" "}
            <span style={{ color: badge.color, fontWeight: 700 }}>← cette page</span>
          </li>
          <li>
            {fr
              ? "Latence moyenne sigma_alert → décision finale < 30s (vs ~3 min avant Phase G)"
              : "Avg sigma_alert → decision latency < 30s (vs ~3 min before Phase G)"}
          </li>
          <li>
            {fr ? "Top-10 attack paths affichés sur " : "Top-10 attack paths shown on "}
            <Link href="/threat-map" style={{ color: "var(--tc-blue)" }}>/threat-map</Link>
          </li>
          <li>
            {fr ? "Top-3 choke points actionnables affichés sur le dashboard" : "Top-3 actionable choke points on the dashboard"}
          </li>
          <li>{fr ? "Tests E2E Playwright passent" : "E2E Playwright tests pass"}</li>
          <li>{fr ? "CHANGELOG entrée + tag v1.1.0" : "CHANGELOG entry + v1.1.0 tag"}</li>
        </ul>
      </div>
    </div>
  );
}

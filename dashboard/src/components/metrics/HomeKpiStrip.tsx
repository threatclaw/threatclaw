"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, ShieldAlert, Target, Bell } from "lucide-react";
import { t as tr, type Locale } from "@/lib/i18n";
import { fetchFindingsCounts, fetchAlertsCounts } from "@/lib/tc-api";

interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface Incident {
  id: number;
  severity: string | null;
  status: string;
}

interface AssetScore {
  asset: string;
  score: number;
}

interface Situation {
  global_score?: number;
  // Rust `SecuritySituation` serializes the per-asset list under the key
  // `assets` (see src/agent/intelligence_engine.rs). Some legacy responses
  // used `asset_situations`; we accept both for forward compatibility.
  assets?: AssetScore[];
  asset_situations?: AssetScore[];
}

function emptyBreakdown(): SeverityBreakdown {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

function bucketSeverity(sev: string | null | undefined, b: SeverityBreakdown): void {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") b.critical += 1;
  else if (s === "HIGH") b.high += 1;
  else if (s === "MEDIUM") b.medium += 1;
  else if (s === "LOW") b.low += 1;
}

function countsToBreakdown(entries: { label: string; count: number }[]): SeverityBreakdown {
  const b = emptyBreakdown();
  for (const e of entries) {
    const s = e.label.toUpperCase();
    if (s === "CRITICAL") b.critical = e.count;
    else if (s === "HIGH") b.high = e.count;
    else if (s === "MEDIUM") b.medium = e.count;
    else if (s === "LOW") b.low = e.count;
  }
  return b;
}

export default function HomeKpiStrip({ locale }: { locale: Locale }) {
  const [openIncidents, setOpenIncidents] = useState<SeverityBreakdown>(emptyBreakdown());
  const [incidentTotal, setIncidentTotal] = useState<number>(0);
  const [findings, setFindings] = useState<SeverityBreakdown>(emptyBreakdown());
  const [topAsset, setTopAsset] = useState<AssetScore | null>(null);
  const [alerts24h, setAlerts24h] = useState<number>(0);

  useEffect(() => {
    let mounted = true;
    void (async () => {
      try {
        const res = await fetch("/api/tc/incidents?status=open&limit=200");
        const data = await res.json();
        const items: Incident[] = data?.incidents ?? [];
        const b = emptyBreakdown();
        for (const i of items) bucketSeverity(i.severity, b);
        if (mounted) {
          setOpenIncidents(b);
          setIncidentTotal(items.length);
        }
      } catch {
        /* endpoint not ready — show zeros */
      }
    })();

    void (async () => {
      try {
        const counts = await fetchFindingsCounts();
        if (mounted) setFindings(countsToBreakdown(counts));
      } catch {
        /* */
      }
    })();

    void (async () => {
      try {
        const counts = await fetchAlertsCounts();
        if (mounted) {
          const total = counts.reduce((acc, c) => acc + c.count, 0);
          setAlerts24h(total);
        }
      } catch {
        /* */
      }
    })();

    void (async () => {
      try {
        const res = await fetch("/api/tc/intelligence/situation");
        const data: Situation = await res.json();
        const raw = data.assets ?? data.asset_situations ?? [];
        const assets = raw.slice();
        // Highest score = most at risk (IE inverts raw risk into score later,
        // but the per-asset score here is a risk number 0-100 where higher
        // means worse — matches what the Status page shows).
        assets.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
        const top = assets[0];
        if (mounted && top) setTopAsset(top);
      } catch {
        /* */
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "10px",
        marginBottom: "16px",
      }}
    >
      <Tile
        icon={<ShieldAlert size={14} color="#d03020" />}
        label={tr("kpiOpenIncidents", locale)}
        value={incidentTotal}
        breakdown={openIncidents}
        href="/incidents?status=open"
      />
      <Tile
        icon={<AlertTriangle size={14} color="#d09020" />}
        label={tr("kpiFindings", locale)}
        value={findings.critical + findings.high + findings.medium + findings.low}
        breakdown={findings}
        href="/findings"
      />
      <TileAsset
        icon={<Target size={14} color="#9060d0" />}
        label={tr("kpiTopRiskAsset", locale)}
        asset={topAsset}
        locale={locale}
      />
      <TileCount
        icon={<Bell size={14} color="#3080d0" />}
        label={tr("kpiAlerts24h", locale)}
        value={alerts24h}
        href="/alerts"
      />
    </div>
  );
}

function Tile({
  icon,
  label,
  value,
  breakdown,
  href,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  breakdown: SeverityBreakdown;
  href: string;
}) {
  return (
    <a
      href={href}
      style={{
        padding: "12px 14px",
        borderRadius: "10px",
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
        textDecoration: "none",
        color: "inherit",
        cursor: "pointer",
        transition: "border-color 120ms, transform 120ms",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--tc-red-border)")}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--tc-border)")}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px", color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {icon}
        {label}
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: "8px" }}>
        <span style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)" }}>{value}</span>
        <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
          <SevChip n={breakdown.critical} bg="rgba(208,48,32,0.15)" fg="#d03020" label="C" />
          <SevChip n={breakdown.high} bg="rgba(208,144,32,0.15)" fg="#d09020" label="H" />
          <SevChip n={breakdown.medium} bg="rgba(48,128,208,0.15)" fg="#3080d0" label="M" />
          <SevChip n={breakdown.low} bg="rgba(48,160,80,0.15)" fg="#30a050" label="L" />
        </span>
      </div>
    </a>
  );
}

function TileCount({
  icon,
  label,
  value,
  href,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  href: string;
}) {
  return (
    <a
      href={href}
      style={{
        padding: "12px 14px",
        borderRadius: "10px",
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
        textDecoration: "none",
        color: "inherit",
        cursor: "pointer",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px", color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {icon}
        {label}
      </div>
      <div style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)" }}>{value}</div>
    </a>
  );
}

function TileAsset({
  icon,
  label,
  asset,
  locale,
}: {
  icon: React.ReactNode;
  label: string;
  asset: AssetScore | null;
  locale: Locale;
}) {
  // IE's per-asset `score` is a *risk* number 0-100 where higher = worse.
  // Every other tile on this strip and the CpuCard speak in *health* 0-100
  // where higher = better. Invert here so the RSSI doesn't have to flip
  // the mental model mid-scan.
  const risk = asset?.score ?? 0;
  const health = Math.max(0, 100 - Math.round(risk));
  const color = !asset
    ? "var(--tc-text-muted)"
    : risk >= 70
      ? "#d03020"
      : risk >= 40
        ? "#d09020"
        : "#30a050";
  return (
    <a
      href="/assets"
      style={{
        padding: "12px 14px",
        borderRadius: "10px",
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
        textDecoration: "none",
        color: "inherit",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px", color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {icon}
        {label}
      </div>
      {asset ? (
        <div>
          <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {asset.asset}
          </div>
          <div style={{ fontSize: "18px", fontWeight: 800, color, marginTop: "2px" }}>
            {health}/100
          </div>
        </div>
      ) : (
        <div style={{ fontSize: "12px", color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "Aucun asset à risque" : "No asset at risk"}
        </div>
      )}
    </a>
  );
}

function SevChip({ n, bg, fg, label }: { n: number; bg: string; fg: string; label: string }) {
  if (n <= 0) return null;
  return (
    <span
      style={{
        background: bg,
        color: fg,
        padding: "1px 5px",
        borderRadius: "4px",
        fontSize: "9px",
        fontWeight: 700,
        marginLeft: "3px",
        letterSpacing: "0.02em",
      }}
    >
      {label}:{n}
    </span>
  );
}

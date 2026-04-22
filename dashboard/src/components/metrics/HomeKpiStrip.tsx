"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, Target, Activity, Clock } from "lucide-react";
import { t as tr, type Locale } from "@/lib/i18n";
import { fetchAlertsCounts } from "@/lib/tc-api";

interface Incident {
  id: number;
  severity: string | null;
  verdict: string;
  status: string;
}

interface AssetScore {
  asset: string;
  score: number;
}

interface Situation {
  global_score?: number;
  assets?: AssetScore[];
  asset_situations?: AssetScore[];
}

function isSevere(s: string | null | undefined): boolean {
  const x = (s ?? "").toUpperCase();
  return x === "HIGH" || x === "CRITICAL";
}

export default function HomeKpiStrip({ locale }: { locale: Locale }) {
  const [pendingCount, setPendingCount] = useState<number>(0);
  const [pendingSevere, setPendingSevere] = useState<number>(0);
  const [confirmedCount, setConfirmedCount] = useState<number>(0);
  const [confirmedSevere, setConfirmedSevere] = useState<number>(0);
  const [topAsset, setTopAsset] = useState<AssetScore | null>(null);
  const [alertsTotal, setAlertsTotal] = useState<number>(0);

  useEffect(() => {
    let mounted = true;
    // ── Incidents (lifetime, not just 'open') — we need confirmed ones too
    void (async () => {
      try {
        const res = await fetch("/api/tc/incidents?limit=2000");
        const data = await res.json();
        const items: Incident[] = data?.incidents ?? [];
        let pending = 0, pendingHigh = 0, confirmed = 0, confirmedHigh = 0;
        for (const i of items) {
          if (i.verdict === "pending") {
            pending += 1;
            if (isSevere(i.severity)) pendingHigh += 1;
          } else if (i.verdict === "confirmed") {
            confirmed += 1;
            if (isSevere(i.severity)) confirmedHigh += 1;
          }
        }
        if (mounted) {
          setPendingCount(pending);
          setPendingSevere(pendingHigh);
          setConfirmedCount(confirmed);
          setConfirmedSevere(confirmedHigh);
        }
      } catch {
        /* endpoint not ready — show zeros */
      }
    })();

    // ── Raw alerts volume (for the triage ratio)
    void (async () => {
      try {
        const counts = await fetchAlertsCounts();
        if (mounted) setAlertsTotal(counts.reduce((acc, c) => acc + c.count, 0));
      } catch {
        /* */
      }
    })();

    // ── Top risk asset (raw risk score, we display inverted health)
    void (async () => {
      try {
        const res = await fetch("/api/tc/intelligence/situation");
        const data: Situation = await res.json();
        const raw = data.assets ?? data.asset_situations ?? [];
        const assets = raw.slice();
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

  // Triage ratio — how much noise did TC filter away? The story is
  // "we turn a firehose into a short actionable list". Guard div-by-zero
  // for fresh installs where counts are still 0.
  const triaged = pendingCount + confirmedCount;
  const noiseReduced = alertsTotal > 0
    ? (1 - triaged / alertsTotal) * 100
    : null;

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "10px",
        marginBottom: "16px",
      }}
    >
      <TileCount
        icon={<Clock size={14} color="#d09020" />}
        label={tr("kpiPendingTriage", locale)}
        value={pendingCount}
        subtle={
          pendingSevere > 0
            ? locale === "fr"
              ? `dont ${pendingSevere} HIGH+`
              : `${pendingSevere} HIGH+`
            : locale === "fr"
              ? "rien d'urgent"
              : "nothing urgent"
        }
        href="/incidents?verdict=pending"
        accent={pendingSevere > 0 ? "#d03020" : "#d09020"}
      />
      <TileCount
        icon={<AlertTriangle size={14} color="#d03020" />}
        label={tr("kpiConfirmedThreats", locale)}
        value={confirmedSevere}
        subtle={
          locale === "fr"
            ? `sur ${confirmedCount} confirmés`
            : `of ${confirmedCount} confirmed`
        }
        href="/incidents?verdict=confirmed"
        accent="#d03020"
      />
      <TileAsset
        icon={<Target size={14} color="#9060d0" />}
        label={tr("kpiTopRiskAsset", locale)}
        asset={topAsset}
        locale={locale}
      />
      <TileTriage
        icon={<ShieldCheck size={14} color="#30a050" />}
        label={tr("kpiTriageRatio", locale)}
        triaged={triaged}
        alertsTotal={alertsTotal}
        noiseReduced={noiseReduced}
        locale={locale}
      />
    </div>
  );
}

function TileCount({
  icon,
  label,
  value,
  subtle,
  href,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  subtle: string;
  href: string;
  accent: string;
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
        transition: "border-color 120ms",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--tc-red-border)")}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--tc-border)")}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px", color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {icon}
        {label}
      </div>
      <div>
        <div style={{ fontSize: "26px", fontWeight: 800, color: value > 0 ? accent : "var(--tc-text)", lineHeight: 1 }}>
          {value}
        </div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "4px" }}>{subtle}</div>
      </div>
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

function TileTriage({
  icon,
  label,
  triaged,
  alertsTotal,
  noiseReduced,
  locale,
}: {
  icon: React.ReactNode;
  label: string;
  triaged: number;
  alertsTotal: number;
  noiseReduced: number | null;
  locale: Locale;
}) {
  const fr = locale === "fr";
  const pct = noiseReduced === null ? "—" : noiseReduced >= 99.99 ? ">99.99%" : `${noiseReduced.toFixed(2)}%`;
  return (
    <a
      href="/incidents"
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
      <div>
        <div style={{ fontSize: "20px", fontWeight: 800, color: "#30a050", lineHeight: 1 }}>
          {pct}
        </div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "4px" }}>
          {fr
            ? `${triaged.toLocaleString("fr")} incidents · ${alertsTotal.toLocaleString("fr")} alertes brutes`
            : `${triaged.toLocaleString("en")} incidents · ${alertsTotal.toLocaleString("en")} raw alerts`}
        </div>
      </div>
    </a>
  );
}

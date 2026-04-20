"use client";

import { useEffect, useState } from "react";

interface TtaMetrics {
  matched_count: number;
  observed_count: number;
  tta_alert_p50_sec: number | null;
  tta_alert_p95_sec: number | null;
  tta_alert_max_sec: number | null;
  tta_ingest_p50_sec: number | null;
}

function fmtDuration(seconds: number | null, locale: string): string {
  if (seconds == null) return "—";
  const fr = locale === "fr";
  const s = Math.round(seconds);
  if (s < 60) return fr ? `${s} s` : `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return fr ? `${m} min` : `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return fr ? `${h} h` : `${h}h`;
  return fr ? `${Math.round(h / 24)} j` : `${Math.round(h / 24)}d`;
}

export default function KevTtaCard({ locale }: { locale: string }) {
  const fr = locale === "fr";
  const [m, setM] = useState<TtaMetrics | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    void (async () => {
      try {
        const r = await fetch("/api/tc/metrics/kev-tta");
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = (await r.json()) as TtaMetrics;
        if (mounted) setM(data);
      } catch (e: any) {
        if (mounted) setErr(e?.message ?? String(e));
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  if (err) {
    return null; // silent — not critical for the home page
  }

  return (
    <div
      style={{
        padding: 14,
        borderRadius: 10,
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
      }}
    >
      <div style={{ fontSize: 11, fontWeight: 600, color: "var(--tc-text-sec)", marginBottom: 10 }}>
        ⚡ {fr
          ? "Vitesse d'alerte CVE CISA KEV (30 derniers jours)"
          : "CISA KEV alert speed (last 30 days)"}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        <Stat
          label={fr ? "Médiane" : "P50"}
          value={fmtDuration(m?.tta_alert_p50_sec ?? null, locale)}
          color="#30a050"
        />
        <Stat
          label="P95"
          value={fmtDuration(m?.tta_alert_p95_sec ?? null, locale)}
          color="#e0a020"
        />
        <Stat
          label={fr ? "CVE matchées" : "Matched"}
          value={`${m?.matched_count ?? 0}`}
          color="var(--tc-blue)"
        />
      </div>
      <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginTop: 8 }}>
        {fr
          ? `${m?.observed_count ?? 0} CVE KEV observées ce mois, ${m?.matched_count ?? 0} impactant vos assets.`
          : `${m?.observed_count ?? 0} KEV CVEs observed this month, ${m?.matched_count ?? 0} affecting your assets.`}
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>
        {label}
      </div>
      <div style={{ fontSize: 20, fontWeight: 700, color, marginTop: 2 }}>{value}</div>
    </div>
  );
}

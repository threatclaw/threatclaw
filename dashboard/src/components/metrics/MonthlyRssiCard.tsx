"use client";

import { useEffect, useState } from "react";

interface Summary {
  incidents_total?: number;
  incidents_confirmed?: number;
  incidents_fp?: number;
  incidents_resolved?: number;
  sev_critical?: number;
  sev_high?: number;
  incidents_with_blast?: number;
  blast_score_max?: number | null;
  mttr_p50_sec?: number | null;
}

interface Report {
  period: string;
  company_name: string;
  summary: Summary;
  top_incidents: Array<{
    id: number;
    title: string;
    asset: string;
    severity: string | null;
    blast_radius_score: number | null;
  }>;
}

function currentYyyyMm(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

function fmtDuration(seconds: number | null | undefined, locale: string): string {
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

export default function MonthlyRssiCard({ locale }: { locale: string }) {
  const fr = locale === "fr";
  const [report, setReport] = useState<Report | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [yyyyMm] = useState(currentYyyyMm());

  useEffect(() => {
    let mounted = true;
    void (async () => {
      try {
        const r = await fetch(`/api/tc/reports/monthly/${yyyyMm}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = (await r.json()) as Report;
        if (mounted) setReport(data);
      } catch (e: any) {
        if (mounted) setErr(e?.message ?? String(e));
      }
    })();
    return () => {
      mounted = false;
    };
  }, [yyyyMm]);

  if (err) {
    return null;
  }

  const s = report?.summary ?? {};
  const total = s.incidents_total ?? 0;
  const confirmed = s.incidents_confirmed ?? 0;
  const resolved = s.incidents_resolved ?? 0;

  return (
    <div
      style={{
        padding: 16,
        borderRadius: 10,
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 12 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: "var(--tc-text-sec)" }}>
          {fr ? "Rapport mensuel" : "Monthly report"}
        </div>
        <div style={{ fontSize: 10, color: "var(--tc-text-muted)" }}>{report?.period ?? yyyyMm}</div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 12 }}>
        <Stat value={total} label={fr ? "Incidents" : "Incidents"} color="var(--tc-text-pri)" />
        <Stat value={confirmed} label={fr ? "Confirmés" : "Confirmed"} color="#ff4040" />
        <Stat value={resolved} label={fr ? "Résolus" : "Resolved"} color="#30a050" />
        <Stat
          value={fmtDuration(s.mttr_p50_sec ?? null, locale)}
          label={fr ? "MTTR médian" : "MTTR P50"}
          color="var(--tc-blue)"
          small
        />
      </div>

      <div style={{ display: "flex", gap: 8 }}>
        <a
          href={`/api/tc/reports/monthly/${yyyyMm}/pdf`}
          target="_blank"
          rel="noopener"
          style={{
            flex: 1,
            textAlign: "center",
            padding: "8px 12px",
            background: "var(--tc-blue)",
            color: "#fff",
            borderRadius: 6,
            fontSize: 11,
            textDecoration: "none",
            fontWeight: 500,
          }}
        >
          📥 {fr ? "Télécharger PDF A4" : "Download PDF A4"}
        </a>
        <a
          href={`/api/tc/reports/monthly/${yyyyMm}`}
          target="_blank"
          rel="noopener"
          style={{
            padding: "8px 12px",
            background: "transparent",
            color: "var(--tc-text-sec)",
            border: "1px solid var(--tc-border)",
            borderRadius: 6,
            fontSize: 11,
            textDecoration: "none",
          }}
        >
          JSON
        </a>
      </div>
    </div>
  );
}

function Stat({
  value,
  label,
  color,
  small = false,
}: {
  value: string | number;
  label: string;
  color: string;
  small?: boolean;
}) {
  return (
    <div>
      <div style={{ fontSize: 10, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>
        {label}
      </div>
      <div style={{ fontSize: small ? 16 : 22, fontWeight: 700, color, marginTop: 2 }}>{value}</div>
    </div>
  );
}

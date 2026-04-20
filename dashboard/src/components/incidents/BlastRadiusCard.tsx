"use client";

import { useState } from "react";
import type { BlastRadiusSnapshot, ReachableAsset } from "@/app/incidents/page";

interface Props {
  incidentId: number;
  snapshot: BlastRadiusSnapshot | null | undefined;
  score: number | null | undefined;
  computedAt: string | null | undefined;
  locale: string;
  onRecomputed?: (snapshot: BlastRadiusSnapshot) => void;
}

const scoreColor = (score: number): string => {
  if (score >= 67) return "#ff2020";
  if (score >= 34) return "#e0a020";
  return "#30a050";
};

const scoreLabel = (score: number, locale: string): string => {
  const fr = locale === "fr";
  if (score >= 67) return fr ? "Risque élevé" : "High risk";
  if (score >= 34) return fr ? "Risque modéré" : "Moderate risk";
  if (score > 0) return fr ? "Risque faible" : "Low risk";
  return fr ? "Impact minimal" : "Minimal impact";
};

const fmtRelative = (iso: string | null | undefined, locale: string): string => {
  if (!iso) return "";
  const fr = locale === "fr";
  const diff = Date.now() - new Date(iso).getTime();
  const min = Math.floor(diff / 60_000);
  if (min < 1) return fr ? "à l'instant" : "just now";
  if (min < 60) return fr ? `il y a ${min} min` : `${min} min ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return fr ? `il y a ${h} h` : `${h}h ago`;
  const d = Math.floor(h / 24);
  return fr ? `il y a ${d} j` : `${d}d ago`;
};

const nodeLabel = (id: string): string => {
  const colonIx = id.indexOf(":");
  return colonIx >= 0 ? id.slice(colonIx + 1) : id;
};

const kindFromId = (id: string): string => {
  const colonIx = id.indexOf(":");
  return colonIx >= 0 ? id.slice(0, colonIx) : "asset";
};

const kindIcon: Record<string, string> = {
  user: "👤",
  host: "🖥️",
  database: "🗄️",
  app: "📦",
  bucket: "🪣",
  vm: "💻",
  data_class: "🔐",
  role: "🎭",
  group: "👥",
  network: "🌐",
};

export default function BlastRadiusCard({
  incidentId,
  snapshot,
  score,
  computedAt,
  locale,
  onRecomputed,
}: Props) {
  const [recomputing, setRecomputing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fr = locale === "fr";

  if (!snapshot || score == null) {
    return null;
  }

  const color = scoreColor(score);
  const label = scoreLabel(score, locale);
  const topReachable = snapshot.reachable.slice(0, 10);

  const recompute = async () => {
    setRecomputing(true);
    setError(null);
    try {
      const res = await fetch(
        `/api/tc/incidents/${incidentId}/blast-radius/recompute`,
        { method: "POST" },
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const fresh = (await res.json()) as BlastRadiusSnapshot;
      onRecomputed?.(fresh);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setRecomputing(false);
    }
  };

  return (
    <div
      style={{
        marginBottom: 16,
        padding: 14,
        borderRadius: 10,
        border: `1px solid ${color}40`,
        background: `linear-gradient(135deg, ${color}10 0%, ${color}05 100%)`,
      }}
    >
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 8,
              background: color,
              color: "#fff",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: 16,
            }}
            aria-label={fr ? "Score blast radius" : "Blast radius score"}
          >
            {score}
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--tc-text-pri)" }}>
              {fr ? "Impact potentiel" : "Potential impact"} — {label}
            </div>
            <div style={{ fontSize: 11, color: "var(--tc-text-sec)" }}>
              {snapshot.reachable_count} {fr ? "assets accessibles en ≤" : "assets reachable within "}
              {snapshot.max_hops} {fr ? "sauts" : "hops"}
              {computedAt && ` · ${fmtRelative(computedAt, locale)}`}
            </div>
          </div>
        </div>
        <button
          onClick={recompute}
          disabled={recomputing}
          style={{
            background: "transparent",
            color: "var(--tc-text-sec)",
            border: "1px solid var(--tc-border)",
            borderRadius: 6,
            padding: "6px 12px",
            fontSize: 11,
            cursor: recomputing ? "wait" : "pointer",
          }}
        >
          {recomputing
            ? fr ? "Calcul..." : "Computing..."
            : fr ? "🔄 Recalculer" : "🔄 Recompute"}
        </button>
      </div>

      {error && (
        <div style={{ fontSize: 11, color: "#ff6060", marginBottom: 10 }}>
          {fr ? "Erreur : " : "Error: "}{error}
        </div>
      )}

      {/* Affected assets list */}
      {topReachable.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: "var(--tc-text-sec)", marginBottom: 6 }}>
            {fr ? "Assets impactés (top " : "Top affected assets ("}
            {topReachable.length})
            {snapshot.reachable_count > topReachable.length &&
              ` / ${snapshot.reachable_count}`}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {topReachable.map((a) => (
              <ReachableAssetRow key={a.id} asset={a} locale={locale} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ReachableAssetRow({ asset, locale }: { asset: ReachableAsset; locale: string }) {
  const fr = locale === "fr";
  const kind = kindFromId(asset.id);
  const icon = kindIcon[kind] ?? "📎";
  const critColor =
    asset.criticality >= 8 ? "#ff4040"
    : asset.criticality >= 5 ? "#e0a020"
    : "#708090";
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "24px 1fr auto auto",
        alignItems: "center",
        gap: 8,
        padding: "6px 10px",
        borderRadius: 6,
        background: "var(--tc-bg-elevated)",
        fontSize: 12,
      }}
    >
      <span style={{ fontSize: 14 }}>{icon}</span>
      <div>
        <div style={{ color: "var(--tc-text-pri)", fontWeight: 500 }}>
          {nodeLabel(asset.id)}
        </div>
        <div style={{ fontSize: 10, color: "var(--tc-text-sec)" }}>
          {kind}
        </div>
      </div>
      <span
        style={{
          fontSize: 10,
          color: critColor,
          background: `${critColor}20`,
          padding: "2px 6px",
          borderRadius: 4,
        }}
        title={fr ? "Criticité" : "Criticality"}
      >
        C{asset.criticality}
      </span>
      <span
        style={{
          fontSize: 10,
          color: "var(--tc-text-sec)",
        }}
        title={fr ? "Nombre de sauts" : "Hops away"}
      >
        {asset.hops} {fr ? "saut(s)" : "hop(s)"}
      </span>
    </div>
  );
}

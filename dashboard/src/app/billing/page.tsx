"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useLocale } from "@/lib/useLocale";

// Phase A.3 of the 2026-04-28 pricing pivot — billable asset gauge.
//
// Polls /api/tc/admin/billable-assets every 60s, renders:
//   - the tier the count currently falls into
//   - a horizontal bar with the position relative to the tier limit
//   - a breakdown by device category
//   - the "what doesn't count" disclosure (discovered, uncertain, demo,
//     inactive) so the operator trusts the number
//
// The license cert that drives the actual gating lands in A.4. For
// now this page is a read-only mirror — anyone can see how many
// assets they would be billed for and which tier that puts them in.

interface BillableResponse {
  billable: number;
  total: number;
  by_category: [string, number][];
  discovered: number;
  inactive: number;
  uncertain: number;
  demo: number;
  computed_at: string;
  error?: string;
}

interface BillingStatus {
  tier: string;
  assets_limit: number | null;
  current_count: number;
  has_cert: boolean;
  expires_at: number | null;
  state:
    | { kind: "within_limit" }
    | { kind: "approaching"; remaining: number }
    | { kind: "over_limit"; over_by: number }
    | { kind: "unlimited" };
}

interface BillingStatusResponse {
  count: BillableResponse;
  billing: BillingStatus;
  computed_at: string;
  error?: string;
}

interface Tier {
  id: "free" | "starter" | "pro" | "business" | "enterprise";
  labelFr: string;
  labelEn: string;
  min: number;
  max: number | null;
  monthly: number | null;
  yearly: number | null;
  color: string;
}

const TIERS: Tier[] = [
  { id: "free", labelFr: "Free", labelEn: "Free", min: 0, max: 50, monthly: 0, yearly: 0, color: "#30a050" },
  { id: "starter", labelFr: "Starter", labelEn: "Starter", min: 50, max: 200, monthly: 99, yearly: 990, color: "#4090ff" },
  { id: "pro", labelFr: "Pro", labelEn: "Pro", min: 200, max: 600, monthly: 249, yearly: 2490, color: "#a060c0" },
  { id: "business", labelFr: "Business", labelEn: "Business", min: 600, max: 1500, monthly: 599, yearly: 5990, color: "#d09020" },
  { id: "enterprise", labelFr: "Enterprise", labelEn: "Enterprise", min: 1500, max: null, monthly: null, yearly: null, color: "#e04040" },
];

function tierForCount(n: number): Tier {
  for (const t of TIERS) {
    if (t.max == null || n <= t.max) return t;
  }
  return TIERS[TIERS.length - 1];
}

const labelStyle: React.CSSProperties = {
  fontSize: "9px",
  fontWeight: 700,
  color: "var(--tc-text-muted)",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  display: "block",
  marginBottom: "4px",
};

const REFRESH_MS = 60_000;

export default function BillingPage() {
  const locale = useLocale();
  const fr = locale === "fr";

  const [data, setData] = useState<BillableResponse | null>(null);
  const [billing, setBilling] = useState<BillingStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  async function fetchData() {
    try {
      // Single round-trip — billing-status wraps the count + the
      // license-manager tier resolution in one response.
      const res = await fetch("/api/tc/admin/billing-status");
      const j = (await res.json()) as BillingStatusResponse;
      if (j.error) throw new Error(j.error);
      setData(j.count);
      setBilling(j.billing);
      setLastFetch(new Date());
    } catch (e: any) {
      setData({
        billable: 0,
        total: 0,
        by_category: [],
        discovered: 0,
        inactive: 0,
        uncertain: 0,
        demo: 0,
        computed_at: new Date().toISOString(),
        error: String(e?.message || e),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, REFRESH_MS);
    return () => clearInterval(iv);
  }, []);

  const billable = data?.billable ?? 0;

  // Tier resolution — prefer the cert-driven tier from the backend.
  // Falls back to "what tier would this count fit into" when no cert
  // is present (Free instance).
  const certTierId = (billing?.tier || "Free").toLowerCase() as Tier["id"];
  const tier =
    TIERS.find((t) => t.id === certTierId) ??
    tierForCount(billable);

  const limit = billing?.assets_limit ?? tier.max;
  const tierProgress =
    limit == null
      ? 1
      : Math.min(1, Math.max(0, (billable - tier.min) / Math.max(1, limit - tier.min)));

  const tierLabel = fr ? tier.labelFr : tier.labelEn;
  const remainingInTier = limit == null ? null : Math.max(0, limit - billable);
  const overTier = billing?.state?.kind === "over_limit";
  const approaching = billing?.state?.kind === "approaching";

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
          {fr ? "Utilisation — quota d'assets" : "Usage — asset quota"}
        </h1>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "8px" }}>
          {fr
            ? "Page de visualisation du quota — pas de paiement ici. ThreatClaw facture par nombre de devices internes activement surveillés. Toutes les fonctionnalités (HITL, Investigation Graphs, Threat Map, rapports NIS2) sont incluses dans tous les tiers."
            : "Quota visualisation page — no payment here. ThreatClaw bills by the count of actively-monitored internal devices. Every feature (HITL, Investigation Graphs, Threat Map, NIS2 reports) is included in every tier."}
        </div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
          {fr ? "Pour souscrire ou upgrader →" : "To subscribe or upgrade →"}{" "}
          <a
            href="https://threatclaw.io/fr/pricing"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--tc-blue)" }}
          >
            threatclaw.io/pricing
          </a>
        </div>
      </div>

      {/* ── Main gauge card ── */}
      <div
        style={{
          background: "var(--tc-bg)",
          border: `1px solid ${tier.color}`,
          borderRadius: "var(--tc-radius-md)",
          padding: "20px 24px",
          marginBottom: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "baseline", gap: "16px", marginBottom: "12px" }}>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            {fr ? "Tier actuel" : "Current tier"}
          </div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 800,
              color: tier.color,
              padding: "3px 10px",
              borderRadius: "3px",
              background: `${tier.color}15`,
              border: `1px solid ${tier.color}40`,
            }}
          >
            {tierLabel.toUpperCase()}
          </div>
          {tier.yearly != null && tier.monthly != null && (
            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
              {tier.monthly} €/mois · {tier.yearly} €/an
            </div>
          )}
          {tier.id === "enterprise" && (
            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
              {fr ? "sur devis" : "custom quote"}
            </div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "baseline", gap: "8px", marginBottom: "10px" }}>
          <span style={{ fontSize: "36px", fontWeight: 800, color: tier.color, fontFamily: "inherit" }}>
            {billable}
          </span>
          <span style={{ fontSize: "13px", color: "var(--tc-text-muted)" }}>
            {fr ? "assets facturables" : "billable assets"}
          </span>
          {limit != null && (
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginLeft: "auto" }}>
              {fr ? "limite tier" : "tier limit"}: {limit}
            </span>
          )}
        </div>

        {/* Tier progress bar */}
        {limit != null && (
          <div
            style={{
              height: "10px",
              background: "var(--tc-input)",
              borderRadius: "5px",
              overflow: "hidden",
              border: "1px solid var(--tc-border)",
              marginBottom: "10px",
              position: "relative",
            }}
          >
            <div
              style={{
                width: `${tierProgress * 100}%`,
                height: "100%",
                background: overTier ? "#e04040" : tier.color,
                transition: "width 600ms ease",
              }}
            />
          </div>
        )}

        {tier.max != null && (
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>
            <span>{tier.min}</span>
            <span>{tier.max}</span>
          </div>
        )}

        {overTier && (
          <div
            style={{
              padding: "10px 12px",
              background: "rgba(224,64,64,0.08)",
              border: "1px solid rgba(224,64,64,0.3)",
              borderRadius: "var(--tc-radius-sm)",
              fontSize: "11px",
              color: "var(--tc-text-sec)",
              marginBottom: "12px",
            }}
          >
            <strong style={{ color: "#e04040" }}>
              {fr ? `Tier ${tier.labelFr} dépassé.` : `${tier.labelEn} tier exceeded.`}
            </strong>
            <br />
            {fr
              ? "Une période de grâce de 7 jours est accordée. Pour upgrader → "
              : "A 7-day grace period applies. To upgrade → "}
            <a
              href="https://threatclaw.io/fr/pricing"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "var(--tc-blue)" }}
            >
              threatclaw.io/pricing
            </a>
          </div>
        )}

        {!overTier && approaching && remainingInTier != null && (
          <div
            style={{
              padding: "10px 12px",
              background: "rgba(208,144,32,0.08)",
              border: "1px solid rgba(208,144,32,0.3)",
              borderRadius: "var(--tc-radius-sm)",
              fontSize: "11px",
              color: "var(--tc-text-sec)",
              marginBottom: "12px",
            }}
          >
            {fr
              ? `Plus que ${remainingInTier} assets avant la limite. Anticipez → `
              : `Only ${remainingInTier} assets remain before the tier limit. Plan ahead → `}
            <a
              href="https://threatclaw.io/fr/pricing"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "var(--tc-blue)" }}
            >
              threatclaw.io/pricing
            </a>
          </div>
        )}

        {data?.by_category && data.by_category.length > 0 && (
          <>
            <label style={labelStyle}>{fr ? "Répartition par type" : "By type"}</label>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
                gap: "6px",
                fontSize: "10px",
              }}
            >
              {data.by_category.map(([cat, n]) => (
                <div
                  key={cat}
                  style={{
                    padding: "4px 8px",
                    background: "var(--tc-input)",
                    border: "1px solid var(--tc-border)",
                    borderRadius: "3px",
                    display: "flex",
                    justifyContent: "space-between",
                  }}
                >
                  <span>{cat}</span>
                  <strong style={{ color: "var(--tc-text)" }}>{n}</strong>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* ── What doesn't count disclosure ── */}
      {data && (
        <div
          style={{
            background: "var(--tc-bg)",
            border: "1px solid var(--tc-border)",
            borderRadius: "var(--tc-radius-md)",
            padding: "16px 20px",
            marginBottom: "16px",
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: 700, marginBottom: "8px", color: "var(--tc-text-sec)" }}>
            {fr ? "Ce qui N'est PAS facturé" : "What is NOT billed"}
          </div>
          <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", lineHeight: 1.6, marginBottom: "10px" }}>
            {fr
              ? `Sur les ${data.total} entrées qu'il y a actuellement dans le graphe, seules ${data.billable} sont facturables. Voici pourquoi :`
              : `Out of ${data.total} entries currently in the graph, only ${data.billable} are billable. Why:`}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "8px", fontSize: "10px" }}>
            <DisclosureRow
              label={fr ? "Découverts (sans event)" : "Discovered (no event yet)"}
              count={data.discovered}
              tooltip={fr ? "ThreatClaw a vu ce device mais aucun finding/alert n'a encore ciblé cet asset. Devient facturable au premier event." : "ThreatClaw has seen this device but no finding/alert has targeted it yet. Becomes billable at first event."}
            />
            <DisclosureRow
              label={fr ? "Inactifs (>30j sans event)" : "Inactive (>30d silent)"}
              count={data.inactive}
              tooltip={fr ? "L'asset n'a pas généré d'event depuis 30 jours. Sort du compte facturable. Réintègre automatiquement au prochain event." : "Asset hasn't fired an event in 30+ days. Excluded from billing. Auto-rejoins on next event."}
            />
            <DisclosureRow
              label={fr ? "Doublons probables" : "Likely duplicates"}
              count={data.uncertain}
              tooltip={fr ? "Dédup ambiguë (DHCP sans MAC, hostname incohérent). Pas facturé tant que non résolu — fixez l'IP statique ou installez un agent pour identifier proprement." : "Ambiguous dedup (DHCP without MAC, inconsistent hostname). Not billed until resolved."}
            />
            <DisclosureRow
              label={fr ? "Données démo" : "Demo data"}
              count={data.demo}
              tooltip={fr ? "Insérées par le wizard de configuration. Toujours exclues." : "Inserted by the setup wizard. Always excluded."}
            />
          </div>
        </div>
      )}

      {/* ── All tiers reference ── */}
      <div
        style={{
          background: "var(--tc-bg)",
          border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)",
          padding: "16px 20px",
          marginBottom: "16px",
        }}
      >
        <div style={{ fontSize: "11px", fontWeight: 700, marginBottom: "4px", color: "var(--tc-text-sec)" }}>
          {fr ? "Tarifs ThreatClaw — référence" : "ThreatClaw pricing — reference"}
        </div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "10px" }}>
          {fr
            ? "Achat sur threatclaw.io/pricing. Cette page est en lecture seule."
            : "Purchase via threatclaw.io/pricing. This page is read-only."}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "8px" }}>
          {TIERS.map((t) => {
            const isCurrent = t.id === tier.id;
            return (
              <div
                key={t.id}
                style={{
                  padding: "10px 12px",
                  background: isCurrent ? `${t.color}10` : "var(--tc-input)",
                  border: `1px solid ${isCurrent ? t.color : "var(--tc-border)"}`,
                  borderRadius: "var(--tc-radius-sm)",
                  fontSize: "10px",
                }}
              >
                <div style={{ fontWeight: 700, color: t.color, marginBottom: "4px" }}>
                  {fr ? t.labelFr : t.labelEn}
                  {isCurrent && (
                    <span style={{ marginLeft: "6px", fontSize: "8px", color: "var(--tc-text-muted)" }}>
                      {fr ? "← actuel" : "← current"}
                    </span>
                  )}
                </div>
                <div style={{ color: "var(--tc-text-muted)", marginBottom: "4px" }}>
                  {t.max == null
                    ? `${t.min}+ ${fr ? "assets" : "assets"}`
                    : `${t.min}-${t.max} ${fr ? "assets" : "assets"}`}
                </div>
                <div style={{ color: "var(--tc-text)" }}>
                  {t.yearly == null ? (fr ? "sur devis" : "custom") : t.yearly === 0 ? "0 €" : `${t.yearly} €/an`}
                </div>
                {t.monthly != null && t.monthly > 0 && (
                  <div style={{ color: "var(--tc-text-muted)", fontSize: "9px" }}>
                    {fr ? "ou" : "or"} {t.monthly} €/mois
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
        {lastFetch && (
          <>
            {fr ? "Mis à jour" : "Updated"} {lastFetch.toLocaleTimeString()} —{" "}
            {fr ? "auto-refresh 60s" : "auto-refresh 60s"}
          </>
        )}
        {!loading && data?.error && (
          <span style={{ marginLeft: "16px", color: "#e04040" }}>{data.error}</span>
        )}
      </div>

      <div style={{ marginTop: "20px", padding: "10px 14px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", fontSize: "11px", color: "var(--tc-text-sec)" }}>
        <strong>{fr ? "Vous avez reçu une clé de licence ?" : "You received a license key?"}</strong>{" "}
        {fr ? "Collez-la sur" : "Paste it on"}{" "}
        <Link href="/licensing" style={{ color: "var(--tc-blue)" }}>/licensing</Link>{" "}
        {fr
          ? "pour activer votre tier (Starter / Pro / Business). Cette page-ci ne sert qu'à visualiser le quota."
          : "to activate your tier (Starter / Pro / Business). This page is read-only."}
      </div>

      <div style={{ marginTop: "12px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
        {fr ? "Voir aussi" : "See also"}:{" "}
        <Link href="/assets" style={{ color: "var(--tc-blue)" }}>/assets</Link>
        {" — "}
        {fr ? "détail de chaque device, override de criticité" : "per-device detail, criticality override"}
      </div>
    </div>
  );
}

function DisclosureRow({ label, count, tooltip }: { label: string; count: number; tooltip: string }) {
  return (
    <div
      title={tooltip}
      style={{
        padding: "8px 10px",
        background: "var(--tc-input)",
        border: "1px solid var(--tc-border)",
        borderRadius: "3px",
        cursor: "help",
      }}
    >
      <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", marginBottom: "2px" }}>{label}</div>
      <div style={{ color: "var(--tc-text)", fontSize: "13px", fontWeight: 700 }}>{count}</div>
    </div>
  );
}

"use client";

/**
 * Page asset dédiée — Phase 10c
 *
 * Remplace le popup `expandedId` qui vivait dans `/assets/page.tsx`.
 *  - URL canonique partageable : `/assets/[assetId]`
 *  - Sidebar gauche : Résumé · Logiciels · Réseau · Sécurité · Findings · Incidents
 *  - Cible le payload agrégé `GET /api/tc/assets/:id/full` (asset + findings +
 *    incidents + scans en 1 round-trip).
 *
 * Cohérence visuelle calquée sur `/investigate/[incidentId]/page.tsx` :
 * mêmes classes `.inv-card`, mêmes variables CSS `var(--tc-*)`.
 */

import React, { useState, useEffect, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import {
  ArrowLeft,
  HelpCircle,
  RefreshCw,
  AlertTriangle,
  ExternalLink,
  Trash2,
} from "lucide-react";
import { PageShell } from "@/components/chrome/PageShell";
import { t as tr, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import {
  Asset,
  Category,
  ICON_MAP,
  CRIT_COLORS,
  SEV_COLORS,
} from "@/lib/asset-shared";
// Phase 11h — components shared with the listing page now live in a
// non-route module so Next.js App Router doesn't choke on cross-page
// named imports.
import {
  ExclusionPanel,
  SecurityTab,
  AssetScanSurface,
  GraphIntelSection,
} from "@/components/assets/sections";

// ── Types backend ──

interface FullPayload {
  asset: Asset;
  findings: Array<{
    id: number;
    skill_id: string;
    title: string;
    severity: string;
    status: string;
    detected_at: string;
    category?: string | null;
    asset?: string | null;
    source?: string | null;
    metadata?: Record<string, unknown>;
  }>;
  incidents: Array<{
    id: number;
    title: string;
    severity: string;
    status: string;
    verdict?: string;
    created_at: string;
    summary?: string;
  }>;
  scans: Array<{
    id: number;
    target: string;
    scan_type: string;
    status: string;
    requested_at: string;
    finished_at?: string | null;
    asset_id?: string | null;
  }>;
  /**
   * Phase 10c-cov — coverage matrix : 6 tuiles déterministes décrivant
   * quels skills voient cet asset et lesquels devraient le voir mais
   * ne le voient pas.
   */
  coverage: Array<{
    kind: string;
    label: string;
    state: "covered" | "gap" | "not_configured";
    detail: string;
    last_seen?: string | null;
    action_hint?: string | null;
  }>;
}

type SectionId =
  | "summary"
  | "software"
  | "network"
  | "security"
  | "findings"
  | "incidents"
  | "coverage";

const SECTIONS: Array<{ id: SectionId; labelFr: string; labelEn: string }> = [
  { id: "summary", labelFr: "Résumé", labelEn: "Summary" },
  { id: "software", labelFr: "Logiciels", labelEn: "Software" },
  { id: "network", labelFr: "Réseau", labelEn: "Network" },
  { id: "security", labelFr: "Sécurité", labelEn: "Security" },
  { id: "findings", labelFr: "Vulnérabilités", labelEn: "Findings" },
  { id: "incidents", labelFr: "Incidents", labelEn: "Incidents" },
  { id: "coverage", labelFr: "Couverture", labelEn: "Coverage" },
];

/**
 * Phase 11c — categories where the "Logiciels" tab adds no value.
 * For a firewall / IoT / printer the package inventory is either
 * unreachable (closed appliance) or conceptually wrong (OS firmware,
 * not user-installed apps). We hide the tab entirely instead of
 * showing "Aucun logiciel détecté" which read as a misconfiguration.
 */
const NO_SOFTWARE_CATEGORIES = new Set([
  "network",
  "iot",
  "ot",
  "mobile",
  "printer",
]);

// ── Helpers ──

function fmtDate(iso: string | null | undefined, locale: Locale): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US", {
      year: "numeric",
      month: "short",
      day: "2-digit",
    });
  } catch {
    return iso;
  }
}

function fmtTime(iso: string | null | undefined, locale: Locale): string {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(locale === "fr" ? "fr-FR" : "en-US", {
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}

const labelStyle: React.CSSProperties = {
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--tc-text-muted)",
  fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
  display: "block",
  marginBottom: 3,
};

// ── Page ──

export default function AssetDetailPage() {
  const router = useRouter();
  const params = useParams();
  const assetId = params?.assetId as string;
  const locale = useLocale();

  const [data, setData] = useState<FullPayload | null>(null);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<SectionId>("summary");

  const load = useCallback(async () => {
    if (!assetId) return;
    setLoading(true);
    setError(null);
    try {
      const [fullRes, catRes] = await Promise.all([
        fetch(`/api/tc/assets/${encodeURIComponent(assetId)}/full`, {
          signal: AbortSignal.timeout(10000),
        }),
        fetch("/api/tc/assets/categories", {
          signal: AbortSignal.timeout(10000),
        }),
      ]);
      if (fullRes.status === 404) {
        setError(locale === "fr" ? "Asset introuvable" : "Asset not found");
        setLoading(false);
        return;
      }
      const full = await fullRes.json();
      if (full?.error) {
        setError(full.error);
        setLoading(false);
        return;
      }
      setData(full);
      const cat = await catRes.json();
      setCategories(cat?.categories || []);
    } catch (e) {
      setError(
        locale === "fr"
          ? "Backend non accessible"
          : "Backend not reachable",
      );
    }
    setLoading(false);
  }, [assetId, locale]);

  useEffect(() => {
    load();
  }, [load]);

  // Phase 11c — if the active tab is hidden for this asset's category
  // (e.g. landed on "software" for a firewall), fall back to the summary
  // so the user never stares at an empty pane.
  useEffect(() => {
    if (
      data &&
      section === "software" &&
      NO_SOFTWARE_CATEGORIES.has(data.asset.category)
    ) {
      setSection("summary");
    }
  }, [data, section]);

  // ── Loading / error states ──

  if (loading) {
    return (
      <PageShell title={locale === "fr" ? "Asset" : "Asset"}>
        <div className="ad-loading">
          <RefreshCw size={14} className="ad-spin" />
          <span>{locale === "fr" ? "Chargement..." : "Loading..."}</span>
        </div>
        <style>{styleBlock}</style>
      </PageShell>
    );
  }

  if (error || !data) {
    return (
      <PageShell title={locale === "fr" ? "Asset" : "Asset"}>
        <div className="ad-error">
          <AlertTriangle size={14} />
          <span>{error || (locale === "fr" ? "Erreur inconnue" : "Unknown error")}</span>
        </div>
        <button onClick={() => router.push("/assets")} className="ad-back-btn">
          <ArrowLeft size={12} />
          <span>{locale === "fr" ? "Retour à l'inventaire" : "Back to inventory"}</span>
        </button>
        <style>{styleBlock}</style>
      </PageShell>
    );
  }

  const asset = data.asset;
  const cat = categories.find((c) => c.id === asset.category);
  const Icon = ICON_MAP[cat?.icon || "help-circle"] || HelpCircle;
  const crit =
    CRIT_COLORS[asset.criticality] || {
      color: "var(--tc-text-muted)",
      label: asset.criticality,
    };

  const software = Array.isArray(asset.software)
    ? asset.software
    : [];
  const services = Array.isArray(asset.services) ? asset.services : [];

  return (
    <PageShell title={asset.name}>
      <style>{styleBlock}</style>
      <div className="ad-wrap">
        {/* Breadcrumb / back */}
        <button onClick={() => router.push("/assets")} className="ad-back-btn">
          <ArrowLeft size={12} />
          <span>{locale === "fr" ? "Inventaire" : "Inventory"}</span>
        </button>

        {/* Hero */}
        <div className={`ad-hero crit-${asset.criticality}`}>
          <div className="ad-hero-left">
            <div className="ad-icon-wrap" style={{ color: cat?.color || "var(--tc-text-muted)" }}>
              <Icon size={28} />
            </div>
            <div>
              <div className="ad-name">{asset.name}</div>
              <div className="ad-tags">
                <span
                  className="ad-tag"
                  style={{
                    background: `${crit.color}15`,
                    color: crit.color,
                    border: `1px solid ${crit.color}30`,
                  }}
                >
                  {crit.label}
                </span>
                <span
                  className="ad-tag"
                  style={{
                    background: "var(--tc-input)",
                    color: "var(--tc-text-muted)",
                    border: "1px solid var(--tc-border)",
                  }}
                >
                  {cat?.label || asset.category}
                </span>
                {/* Phase 11e — public_ip shadow badge. Operators see at a
                    glance that this row is not a billable asset but a
                    log-surfaced IP that may belong to an existing host. */}
                {(asset.tags || []).includes("public_ip") && (
                  <span
                    className="ad-tag"
                    style={{
                      background: "rgba(48,128,208,0.10)",
                      color: "#3080d0",
                      border: "1px solid rgba(48,128,208,0.30)",
                    }}
                    title={tr("assetDetail_publicIpBadgeTitle", locale)}
                  >
                    {tr("assetDetail_publicIp", locale)}
                  </span>
                )}
                {asset.hostname && (
                  <span className="ad-host">{asset.hostname}</span>
                )}
                {asset.ip_addresses?.length > 0 && (
                  <span className="ad-ip">{asset.ip_addresses.join(" · ")}</span>
                )}
              </div>
            </div>
          </div>
          <div className="ad-hero-right">
            <button
              className="ad-edit-btn"
              onClick={() => router.push(`/assets?edit=${encodeURIComponent(asset.id)}`)}
            >
              {locale === "fr" ? "Modifier" : "Edit"}
            </button>
          </div>
        </div>

        {/* Layout: sidebar + content */}
        <div className="ad-grid">
          <nav className="ad-side">
            {SECTIONS.filter(
              (s) =>
                !(
                  s.id === "software" &&
                  NO_SOFTWARE_CATEGORIES.has(asset.category)
                ),
            ).map((s) => {
              const count =
                s.id === "findings"
                  ? // The "Vulnérabilités" tab is CVE findings only — sigma
                    // detections and ML/behavioral findings belong in Incidents.
                    data.findings.filter((f) => f.category === "software-vuln")
                      .length
                  : s.id === "incidents"
                    ? data.incidents.length
                    : s.id === "software"
                      ? software.length
                      : s.id === "coverage"
                        ? // Show only the count of skills not yet covered (gap +
                          // not_configured) so the badge highlights what needs
                          // attention rather than the trivially-covered ones.
                          data.coverage.filter((c) => c.state !== "covered").length
                        : null;
              return (
                <button
                  key={s.id}
                  onClick={() => setSection(s.id)}
                  className={`ad-side-btn ${section === s.id ? "ad-active" : ""}`}
                >
                  <span>{locale === "fr" ? s.labelFr : s.labelEn}</span>
                  {count !== null && count > 0 && (
                    <span className="ad-side-count">{count}</span>
                  )}
                </button>
              );
            })}
          </nav>

          <main className="ad-main">
            {section === "summary" && (
              <SectionSummary
                asset={asset}
                onAssetUpdated={(next) =>
                  setData((prev) => (prev ? { ...prev, asset: next } : prev))
                }
              />
            )}

            {section === "software" && <SectionSoftware software={software} />}

            {section === "network" && (
              <SectionNetwork asset={asset} services={services} />
            )}

            {section === "security" && (
              <div className="inv-card">
                <div className="inv-card-head">
                  <div className="inv-card-head-left">
                    <strong>{locale === "fr" ? "Sécurité" : "Security"}</strong>
                  </div>
                </div>
                <div style={{ padding: 16 }}>
                  <SecurityTab assetId={asset.id} />
                </div>
              </div>
            )}

            {section === "findings" && (
              <SectionFindings findings={data.findings} />
            )}

            {section === "incidents" && (
              <SectionIncidents incidents={data.incidents} />
            )}

            {section === "coverage" && (
              <SectionCoverage coverage={data.coverage} />
            )}

            {/* Always-visible secondary panels at the bottom of every tab */}
            <div className="ad-sec-panels">
              <ExclusionPanel asset={asset} onChanged={load} />
              <DangerZone
                asset={asset}
                onDeleted={() => router.push("/assets")}
                onMerged={(canonicalId) =>
                  router.push(`/assets/${encodeURIComponent(canonicalId)}`)
                }
              />
            </div>
          </main>
        </div>
      </div>
    </PageShell>
  );
}

// ── Sections ──

function SectionSummary({
  asset,
  onAssetUpdated,
}: {
  asset: Asset;
  onAssetUpdated: (next: Asset) => void;
}) {
  const locale = useLocale();
  const updateCriticality = async (next: string) => {
    const prev = asset.criticality;
    onAssetUpdated({ ...asset, criticality: next });
    try {
      const res = await fetch(
        `/api/tc/assets/${encodeURIComponent(asset.id)}/criticality`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ criticality: next }),
        },
      );
      const j = await res.json().catch(() => ({}));
      if (j?.error) {
        onAssetUpdated({ ...asset, criticality: prev });
        alert(tr("assetDetail_critNotSaved", locale) + j.error);
      }
    } catch {
      onAssetUpdated({ ...asset, criticality: prev });
      alert(tr("assetDetail_critNotSavedNetwork", locale));
    }
  };

  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("assetDetail_summary", locale)}</strong> · {tr("assetDetail_assetIdentity", locale)}
        </div>
        <div className="inv-card-head-right">
          {tr("assetDetail_sourceLabel", locale)} · {asset.source}
        </div>
      </div>
      <div style={{ padding: 18 }}>
        <div className="ad-summary-grid">
          <Field label="IP">
            <span style={{ fontFamily: "monospace" }}>
              {asset.ip_addresses?.join(", ") || "—"}
            </span>
          </Field>
          <Field label="MAC">
            <span style={{ fontFamily: "monospace" }}>
              {asset.mac_address || "—"}
              {asset.mac_vendor && (
                <span style={{ color: "var(--tc-text-muted)" }}> ({asset.mac_vendor})</span>
              )}
            </span>
          </Field>
          <Field label="Hostname">
            {asset.hostname || "—"}
            {asset.fqdn ? ` (${asset.fqdn})` : ""}
          </Field>
          <Field label="OS">{asset.os || "—"}</Field>
          <Field label={tr("assetDetail_role", locale)}>{asset.role || "—"}</Field>
          <Field label={tr("assetDetail_owner", locale)}>{asset.owner || "—"}</Field>
          <Field label={tr("assetDetail_criticality", locale)}>
            <select
              value={asset.criticality}
              onChange={(e) => updateCriticality(e.target.value)}
              className="ad-crit-select"
            >
              <option value="low">{tr("assetDetail_critLow", locale)}</option>
              <option value="medium">{tr("assetDetail_critMedium", locale)}</option>
              <option value="high">{tr("assetDetail_critHigh", locale)}</option>
              <option value="critical">{tr("assetDetail_critEssential", locale)}</option>
              <option value="unknown">{tr("assetDetail_critUnknown", locale)}</option>
            </select>
          </Field>
          <Field label={tr("assetDetail_location", locale)}>{asset.location || "—"}</Field>
          {asset.url && /^https?:\/\//i.test(asset.url) && (
            <div style={{ gridColumn: "1/3" }}>
              <span style={labelStyle}>URL</span>
              <a
                href={asset.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  color: "var(--tc-blue)",
                  fontFamily: "monospace",
                  fontSize: 11,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                {asset.url}
                <ExternalLink size={10} />
              </a>
            </div>
          )}
        </div>

        <GraphIntelSection assetId={asset.id} />

        {asset.tags && asset.tags.length > 0 && (
          <div style={{ marginTop: 14 }}>
            <span style={labelStyle}>Tags</span>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {asset.tags.map((t) => (
                <span key={t} className="ad-soft-tag">
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {asset.notes && (
          <div style={{ marginTop: 12 }}>
            <span style={labelStyle}>Notes</span>
            <div
              style={{
                fontSize: 11,
                color: "var(--tc-text-sec)",
                fontStyle: "italic",
              }}
            >
              {asset.notes}
            </div>
          </div>
        )}

        <div className="ad-summary-foot">
          <span>
            {tr("assetDetail_firstSeen", locale)} · {fmtDate(asset.first_seen, locale)} {fmtTime(asset.first_seen, locale)}
          </span>
          <span>
            {tr("assetDetail_lastSeen", locale)} · {fmtDate(asset.last_seen, locale)} {fmtTime(asset.last_seen, locale)}
          </span>
          {asset.sources && asset.sources.length > 0 && (
            <span>{tr("assetDetail_sources", locale)} · {asset.sources.join(", ")}</span>
          )}
        </div>
      </div>
    </div>
  );
}

function SectionSoftware({ software }: { software: Array<{ name: string; version?: string; source?: string }> }) {
  const locale = useLocale();
  if (software.length === 0) {
    return (
      <div className="inv-card">
        <div className="inv-card-head">
          <div className="inv-card-head-left">
            <strong>{tr("assetDetail_software", locale)}</strong>
          </div>
        </div>
        <div className="ad-empty">
          {tr("assetDetail_noSoftware", locale)}
        </div>
      </div>
    );
  }
  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("assetDetail_software", locale)}</strong> · {software.length}{" "}
          {software.length > 1
            ? tr("assetDetail_entriesPlural", locale)
            : tr("assetDetail_entry", locale)}
        </div>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table className="ad-table">
          <thead>
            <tr>
              <th>{tr("assetDetail_name", locale)}</th>
              <th>Version</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {software.map((s, i) => (
              <tr key={`${s.name}-${i}`}>
                <td style={{ color: "var(--tc-text)", fontWeight: 600 }}>{s.name}</td>
                <td style={{ fontFamily: "monospace", color: "var(--tc-text-sec)" }}>
                  {s.version || "—"}
                </td>
                <td style={{ color: "var(--tc-text-muted)" }}>{s.source || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SectionNetwork({
  asset,
  services,
}: {
  asset: Asset;
  services: Array<{
    port: number;
    proto?: string;
    service?: string;
    product?: string;
    version?: string;
  }>;
}) {
  const locale = useLocale();
  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("assetDetail_network", locale)}</strong> · {tr("assetDetail_exposedServices", locale)}
        </div>
      </div>
      <div style={{ padding: 16 }}>
        <AssetScanSurface asset={asset} />
        {services.length === 0 ? (
          <div className="ad-empty" style={{ marginTop: 12 }}>
            {tr("assetDetail_noNetworkService", locale)}
          </div>
        ) : (
          <div style={{ marginTop: 16 }}>
            <span style={labelStyle}>{tr("assetDetail_servicesPorts", locale)} ({services.length})</span>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {services.map((s, i) => (
                <span key={`${s.port}-${i}`} className="ad-svc-chip">
                  <span style={{ fontWeight: 700, color: "var(--tc-blue)" }}>
                    {s.port}
                  </span>
                  <span style={{ color: "var(--tc-text-muted)" }}>/</span>
                  <span>{s.proto || "tcp"}</span>
                  {s.service && (
                    <span style={{ color: "var(--tc-text-sec)" }}>
                      {s.service}
                    </span>
                  )}
                  {s.product && (
                    <span style={{ color: "#d09020", fontWeight: 600 }}>
                      {s.product}
                    </span>
                  )}
                  {s.version && (
                    <span style={{ color: "var(--tc-text-muted)", fontSize: 9 }}>
                      v{s.version}
                    </span>
                  )}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SectionFindings({
  findings,
}: {
  findings: FullPayload["findings"];
}) {
  const locale = useLocale();
  // This tab is the asset's software VULNERABILITIES — CVE findings only. Sigma
  // detections (PowerShell, reflective loader, ...) and ML/behavioral findings are
  // not vulnerabilities and belong in Incidents, so they are filtered out here.
  const vulns = findings.filter((f) => f.category === "software-vuln");
  if (vulns.length === 0) {
    return (
      <div className="inv-card">
        <div className="inv-card-head">
          <div className="inv-card-head-left">
            <strong>{tr("assetDetail_findings", locale)}</strong>
          </div>
        </div>
        <div className="ad-empty">
          {tr("assetDetail_noFindings", locale)}
        </div>
      </div>
    );
  }
  // Sort: severity desc → date desc.
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  const sorted = [...vulns].sort((a, b) => {
    const sa = order[(a.severity?.toLowerCase() as keyof typeof order)] ?? 5;
    const sb = order[(b.severity?.toLowerCase() as keyof typeof order)] ?? 5;
    if (sa !== sb) return sa - sb;
    return (b.detected_at || "").localeCompare(a.detected_at || "");
  });
  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("assetDetail_findings", locale)}</strong> · {sorted.length}{" "}
          {sorted.length > 1
            ? tr("assetDetail_entriesPlural", locale)
            : tr("assetDetail_entry", locale)}
        </div>
      </div>
      <div className="ad-list">
        {sorted.map((f) => {
          const sev = (f.severity || "info").toLowerCase();
          const sevColor = SEV_COLORS[sev] || "#888";
          return (
            <a key={f.id} href={`/findings`} className="ad-list-row">
              <span
                className="ad-sev"
                style={{
                  background: `${sevColor}15`,
                  color: sevColor,
                  border: `1px solid ${sevColor}30`,
                }}
              >
                {sev}
              </span>
              <span className="ad-list-title">{f.title}</span>
              <span className="ad-list-meta">{f.source || f.skill_id}</span>
              <span className="ad-list-date">{fmtDate(f.detected_at, locale)}</span>
            </a>
          );
        })}
      </div>
    </div>
  );
}

function SectionIncidents({
  incidents,
}: {
  incidents: FullPayload["incidents"];
}) {
  const locale = useLocale();
  if (incidents.length === 0) {
    return (
      <div className="inv-card">
        <div className="inv-card-head">
          <div className="inv-card-head-left">
            <strong>{tr("assetDetail_incidents", locale)}</strong> · {tr("assetDetail_history", locale)}
          </div>
        </div>
        <div className="ad-empty">
          {tr("assetDetail_noIncidents", locale)}
        </div>
      </div>
    );
  }
  // Recent first.
  const sorted = [...incidents].sort((a, b) =>
    (b.created_at || "").localeCompare(a.created_at || ""),
  );
  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("assetDetail_incidents", locale)}</strong> · {incidents.length}{" "}
          {incidents.length > 1
            ? tr("assetDetail_historyPlural", locale)
            : tr("assetDetail_history", locale)}
        </div>
      </div>
      <div className="ad-list">
        {sorted.map((inc) => {
          const sev = (inc.severity || "info").toLowerCase();
          const sevColor = SEV_COLORS[sev] || "#888";
          return (
            <a
              key={inc.id}
              href={`/investigate/${inc.id}`}
              className="ad-list-row"
            >
              <span
                className="ad-sev"
                style={{
                  background: `${sevColor}15`,
                  color: sevColor,
                  border: `1px solid ${sevColor}30`,
                }}
              >
                {sev}
              </span>
              <span className="ad-list-title">
                #{inc.id} — {inc.title}
              </span>
              <span className="ad-list-meta">{inc.status}</span>
              <span className="ad-list-date">{fmtDate(inc.created_at, locale)}</span>
            </a>
          );
        })}
      </div>
    </div>
  );
}

function SectionCoverage({
  coverage,
}: {
  coverage: FullPayload["coverage"];
}) {
  const locale = useLocale();
  const covered = coverage.filter((c) => c.state === "covered").length;
  const gaps = coverage.filter((c) => c.state === "gap").length;
  const missing = coverage.filter((c) => c.state === "not_configured").length;

  // Sort: gaps first (the actionable category), then not_configured, then
  // covered. The RSSI's eyes land on what needs attention, not on what's
  // already fine.
  const order = { gap: 0, not_configured: 1, covered: 2 } as const;
  const sorted = [...coverage].sort(
    (a, b) => (order[a.state] ?? 3) - (order[b.state] ?? 3),
  );

  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("assetDetail_coverage", locale)}</strong> · {tr("assetDetail_whoSeesAsset", locale)}
        </div>
        <div className="inv-card-head-right">
          {covered}{" "}
          {covered > 1
            ? tr("assetDetail_coveredPlural", locale)
            : tr("assetDetail_covered", locale)}{" "}
          · {gaps} gap{gaps > 1 ? "s" : ""} · {missing}{" "}
          {missing > 1
            ? tr("assetDetail_notConfiguredPlural", locale)
            : tr("assetDetail_notConfigured", locale)}
        </div>
      </div>
      <div className="ad-cov-grid">
        {sorted.map((c) => {
          const stateColor =
            c.state === "covered"
              ? "#30a050"
              : c.state === "gap"
                ? "#d09020"
                : "#888";
          const stateBadge =
            c.state === "covered"
              ? "OK"
              : c.state === "gap"
                ? "GAP"
                : "ABSENT";
          const lastSeen = c.last_seen ? fmtDate(c.last_seen, locale) : null;
          return (
            <div
              key={c.kind}
              className="ad-cov-tile"
              style={{ borderLeft: `3px solid ${stateColor}` }}
            >
              <div className="ad-cov-tile-head">
                <span className="ad-cov-label">{c.label}</span>
                <span
                  className="ad-cov-badge"
                  style={{
                    background: `${stateColor}15`,
                    color: stateColor,
                    border: `1px solid ${stateColor}30`,
                  }}
                >
                  {stateBadge}
                </span>
              </div>
              <div className="ad-cov-detail">{c.detail}</div>
              {lastSeen && (
                <div className="ad-cov-meta">
                  {tr("assetDetail_lastObservation", locale)} · {lastSeen}
                </div>
              )}
              {c.action_hint && (
                <div className="ad-cov-action">
                  → {c.action_hint}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DangerZone({
  asset,
  onDeleted,
  onMerged,
}: {
  asset: Asset;
  onDeleted: () => void;
  onMerged: (canonicalId: string) => void;
}) {
  const locale = useLocale();
  const [busy, setBusy] = useState(false);
  const [showMerge, setShowMerge] = useState(false);
  const handleDelete = async () => {
    if (
      !confirm(
        tr("assetDetail_confirmDeletePrefix", locale) +
          ` « ${asset.name} » ` +
          tr("assetDetail_confirmDeleteSuffix", locale),
      )
    )
      return;
    setBusy(true);
    try {
      await fetch(`/api/tc/assets/${encodeURIComponent(asset.id)}`, {
        method: "DELETE",
      });
      onDeleted();
    } catch {
      alert(tr("assetDetail_deleteFailed", locale));
    }
    setBusy(false);
  };
  return (
    <>
      <div className="ad-danger">
        <button
          onClick={() => setShowMerge(true)}
          className="ad-merge-btn"
          title={tr("assetDetail_mergeButtonTitle", locale)}
        >
          <ExternalLink size={11} />
          <span>{tr("assetDetail_linkToAnother", locale)}</span>
        </button>
        <button
          onClick={handleDelete}
          disabled={busy}
          className="ad-delete-btn"
        >
          <Trash2 size={11} />
          <span>{busy ? tr("assetDetail_deleting", locale) : tr("assetDetail_deleteAsset", locale)}</span>
        </button>
      </div>
      {showMerge && (
        <MergeModal
          asset={asset}
          onClose={() => setShowMerge(false)}
          onSuccess={(canonicalId) => {
            setShowMerge(false);
            onMerged(canonicalId);
          }}
        />
      )}
    </>
  );
}

/**
 * Phase 11g — modale de fusion. Permet à l'opérateur de transformer
 * cet asset en alias d'un autre asset existant (ex: shadow d'IP publique
 * créé par les logs firewall, lié à l'asset OPNsense canonique). Le
 * backend POST /api/tc/assets/merge gère l'audit (V68 merge_aliases).
 */
function MergeModal({
  asset,
  onClose,
  onSuccess,
}: {
  asset: Asset;
  onClose: () => void;
  onSuccess: (canonicalId: string) => void;
}) {
  const locale = useLocale();
  const [search, setSearch] = useState("");
  const [candidates, setCandidates] = useState<Asset[]>([]);
  const [picked, setPicked] = useState<Asset | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load candidates once. Backend filtering is overkill at SMB scale —
  // we fetch everything (limit 500) and filter client-side as the user
  // types. ESC closes the modal.
  useEffect(() => {
    fetch(`/api/tc/assets?limit=500`)
      .then((r) => r.json())
      .then((d) => {
        const all: Asset[] = d?.assets || [];
        setCandidates(all.filter((a) => a.id !== asset.id));
      })
      .catch(() => setError(tr("assetDetail_loadAssetsFailed", locale)));
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [asset.id, onClose]);

  const filtered = candidates.filter((a) => {
    const q = search.trim().toLowerCase();
    if (!q) return true;
    return (
      a.name.toLowerCase().includes(q) ||
      (a.hostname || "").toLowerCase().includes(q) ||
      (a.ip_addresses || []).some((ip) => ip.includes(q)) ||
      a.id.toLowerCase().includes(q)
    );
  });

  const submit = async () => {
    if (!picked) {
      setError(tr("assetDetail_selectCanonical", locale));
      return;
    }
    if (!reason.trim()) {
      setError(tr("assetDetail_reasonRequired", locale));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/tc/assets/merge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          canonical_id: picked.id,
          alias_ids: [asset.id],
          reason: reason.trim(),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (data?.error) {
        setError(data.error);
      } else {
        onSuccess(picked.id);
      }
    } catch (e) {
      setError(tr("assetDetail_mergeNetworkError", locale));
    }
    setBusy(false);
  };

  return (
    <div
      className="ad-modal-bg"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="ad-modal">
        <div className="ad-modal-head">
          <strong>{tr("assetDetail_mergeModalTitlePrefix", locale)} « {asset.name} » {tr("assetDetail_mergeModalTitleSuffix", locale)}</strong>
          <button onClick={onClose} className="ad-modal-close">
            ×
          </button>
        </div>
        <div className="ad-modal-body">
          <p className="ad-modal-desc">
            {tr("assetDetail_mergeModalDesc", locale)}
          </p>

          <input
            type="text"
            placeholder={tr("assetDetail_mergeSearchPlaceholder", locale)}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="ad-modal-input"
            autoFocus
          />

          <div className="ad-modal-list">
            {filtered.length === 0 ? (
              <div className="ad-empty">{tr("assetDetail_noAssetFound", locale)}</div>
            ) : (
              filtered.slice(0, 100).map((a) => (
                <button
                  key={a.id}
                  onClick={() => setPicked(a)}
                  className={`ad-modal-cand ${picked?.id === a.id ? "ad-picked" : ""}`}
                >
                  <span className="ad-modal-cand-name">{a.name}</span>
                  <span className="ad-modal-cand-meta">
                    {a.hostname && <>{a.hostname} · </>}
                    {(a.ip_addresses || []).join(", ") || "—"}
                  </span>
                </button>
              ))
            )}
          </div>

          <textarea
            placeholder={tr("assetDetail_reasonPlaceholder", locale)}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="ad-modal-reason"
            rows={2}
          />

          {error && <div className="ad-modal-error">{error}</div>}

          <div className="ad-modal-actions">
            <button onClick={onClose} className="ad-modal-cancel">
              {tr("assetDetail_cancel", locale)}
            </button>
            <button
              onClick={submit}
              disabled={busy || !picked || !reason.trim()}
              className="ad-modal-confirm"
            >
              {busy ? tr("assetDetail_merging", locale) : tr("assetDetail_confirmMerge", locale)}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Helpers UI ──

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <span style={labelStyle}>{label}</span>
      <div style={{ color: "var(--tc-text)", fontSize: 11 }}>{children}</div>
    </div>
  );
}

// ── Styles ──

const styleBlock = `
.ad-wrap {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 0 40px;
}
.ad-back-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px 4px 6px;
  font-size: 10px;
  font-weight: 600;
  font-family: inherit;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  background: transparent;
  border: 1px solid var(--tc-border);
  color: var(--tc-text-muted);
  cursor: pointer;
  margin-bottom: 14px;
  transition: all 150ms;
}
.ad-back-btn:hover {
  color: var(--tc-text);
  border-color: var(--tc-text-muted);
}
.ad-hero {
  background: var(--tc-surface);
  border: 1px solid var(--tc-border);
  border-left: 3px solid var(--tc-text-muted);
  padding: 18px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.ad-hero.crit-critical { border-left-color: #e04040; }
.ad-hero.crit-high { border-left-color: #d07020; }
.ad-hero.crit-medium { border-left-color: #d09020; }
.ad-hero.crit-low { border-left-color: #30a050; }
.ad-hero-left {
  display: flex;
  align-items: center;
  gap: 14px;
}
.ad-icon-wrap {
  width: 44px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
}
.ad-name {
  font-size: 18px;
  font-weight: 800;
  color: var(--tc-text);
}
.ad-tags {
  display: flex;
  gap: 6px;
  margin-top: 4px;
  flex-wrap: wrap;
  align-items: center;
}
.ad-tag {
  font-size: 9px;
  font-weight: 700;
  padding: 2px 7px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-host {
  font-size: 10px;
  color: var(--tc-text-sec);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-ip {
  font-size: 10px;
  color: var(--tc-text-muted);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-edit-btn {
  padding: 6px 12px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-family: inherit;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  color: var(--tc-text-sec);
  cursor: pointer;
}
.ad-edit-btn:hover {
  color: var(--tc-text);
  border-color: var(--tc-text-muted);
}
.ad-grid {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 18px;
  align-items: start;
}
@media (max-width: 800px) {
  .ad-grid {
    grid-template-columns: 1fr;
  }
}
.ad-side {
  display: flex;
  flex-direction: column;
  gap: 1px;
  background: var(--tc-surface);
  border: 1px solid var(--tc-border);
}
.ad-side-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  font-size: 11px;
  font-weight: 600;
  font-family: inherit;
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--tc-border);
  color: var(--tc-text-muted);
  cursor: pointer;
  text-align: left;
  transition: all 100ms;
}
.ad-side-btn:last-child { border-bottom: none; }
.ad-side-btn:hover {
  color: var(--tc-text);
  background: var(--tc-surface-alt);
}
.ad-side-btn.ad-active {
  color: var(--tc-text);
  background: var(--tc-surface-alt);
  border-left: 3px solid var(--tc-red);
  padding-left: 11px;
}
.ad-side-count {
  font-size: 9px;
  font-weight: 700;
  font-family: ui-monospace, 'JetBrains Mono', monospace;
  padding: 1px 6px;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  color: var(--tc-text-muted);
}
.ad-active .ad-side-count {
  color: var(--tc-red);
  border-color: var(--tc-red-border);
}
.ad-main {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.ad-summary-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px 22px;
  font-size: 11px;
}
.ad-summary-foot {
  margin-top: 14px;
  padding-top: 10px;
  border-top: 1px solid var(--tc-border);
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  font-size: 9px;
  color: var(--tc-text-muted);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-crit-select {
  width: 100%;
  padding: 4px 6px;
  font-size: 11px;
  font-family: inherit;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  color: var(--tc-text);
  cursor: pointer;
}
.ad-soft-tag {
  font-size: 9px;
  padding: 2px 6px;
  background: rgba(48,128,208,0.08);
  color: var(--tc-blue);
  border: 1px solid rgba(48,128,208,0.15);
}
.ad-empty {
  padding: 32px 16px;
  text-align: center;
  font-size: 11px;
  color: var(--tc-text-muted);
}
.ad-table {
  width: 100%;
  font-size: 11px;
  border-collapse: collapse;
}
.ad-table th {
  padding: 8px 12px;
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--tc-text-muted);
  text-align: left;
  border-bottom: 1px solid var(--tc-border);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
  background: var(--tc-surface-alt);
}
.ad-table td {
  padding: 7px 12px;
  border-bottom: 1px dashed var(--tc-border);
}
.ad-table tr:last-child td { border-bottom: none; }
.ad-list {
  display: flex;
  flex-direction: column;
}
.ad-list-row {
  display: grid;
  grid-template-columns: 80px 1fr auto auto;
  gap: 12px;
  align-items: center;
  padding: 9px 14px;
  font-size: 11px;
  text-decoration: none;
  border-bottom: 1px dashed var(--tc-border);
  color: var(--tc-text);
  transition: background 100ms;
}
.ad-list-row:last-child { border-bottom: none; }
.ad-list-row:hover { background: var(--tc-surface-alt); }
.ad-sev {
  font-size: 9px;
  font-weight: 700;
  padding: 2px 7px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-family: ui-monospace, 'JetBrains Mono', monospace;
  text-align: center;
}
.ad-list-title {
  color: var(--tc-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ad-list-meta {
  font-size: 10px;
  color: var(--tc-text-muted);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-list-date {
  font-size: 10px;
  color: var(--tc-text-muted);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
  white-space: nowrap;
}
.ad-svc-chip {
  font-size: 10px;
  padding: 3px 8px;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.ad-sec-panels {
  margin-top: 14px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.ad-danger {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding-top: 6px;
  flex-wrap: wrap;
}
.ad-merge-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 6px 12px;
  font-size: 10px;
  font-weight: 600;
  font-family: inherit;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  color: var(--tc-text-sec);
  cursor: pointer;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.ad-merge-btn:hover {
  color: var(--tc-text);
  border-color: var(--tc-text-muted);
}
.ad-modal-bg {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.55);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
}
.ad-modal {
  background: var(--tc-bg);
  border: 1px solid var(--tc-border);
  width: 600px;
  max-width: 100%;
  max-height: 86vh;
  display: flex;
  flex-direction: column;
}
.ad-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--tc-border);
  background: var(--tc-surface-alt);
  font-size: 12px;
  color: var(--tc-text);
}
.ad-modal-close {
  background: none;
  border: none;
  color: var(--tc-text-muted);
  font-size: 22px;
  cursor: pointer;
  line-height: 1;
}
.ad-modal-body {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px 16px;
  overflow-y: auto;
}
.ad-modal-desc {
  font-size: 11px;
  color: var(--tc-text-muted);
  margin: 0;
  line-height: 1.5;
}
.ad-modal-input,
.ad-modal-reason {
  width: 100%;
  padding: 8px 10px;
  font-size: 12px;
  font-family: inherit;
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  color: var(--tc-text);
}
.ad-modal-list {
  display: flex;
  flex-direction: column;
  max-height: 260px;
  overflow-y: auto;
  border: 1px solid var(--tc-border);
}
.ad-modal-cand {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  padding: 8px 12px;
  font-family: inherit;
  background: transparent;
  border: none;
  border-bottom: 1px dashed var(--tc-border);
  cursor: pointer;
  text-align: left;
  transition: background 100ms;
}
.ad-modal-cand:last-child { border-bottom: none; }
.ad-modal-cand:hover { background: var(--tc-surface-alt); }
.ad-modal-cand.ad-picked {
  background: rgba(112,48,160,0.08);
  border-left: 3px solid #7030a0;
  padding-left: 9px;
}
.ad-modal-cand-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--tc-text);
}
.ad-modal-cand-meta {
  font-size: 10px;
  color: var(--tc-text-muted);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-modal-error {
  font-size: 11px;
  color: #ff4040;
  padding: 6px 8px;
  background: rgba(255,64,64,0.08);
  border-left: 2px solid #ff4040;
}
.ad-modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
.ad-modal-cancel,
.ad-modal-confirm {
  padding: 7px 14px;
  font-size: 11px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  border: 1px solid var(--tc-border);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.ad-modal-cancel {
  background: transparent;
  color: var(--tc-text-muted);
}
.ad-modal-confirm {
  background: var(--tc-red);
  border-color: var(--tc-red);
  color: #fff;
}
.ad-modal-confirm:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.ad-delete-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 6px 12px;
  font-size: 10px;
  font-weight: 600;
  font-family: inherit;
  background: rgba(208,48,32,0.06);
  border: 1px solid var(--tc-red-border);
  color: #d03020;
  cursor: pointer;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.ad-delete-btn:disabled { opacity: 0.5; cursor: wait; }
.ad-cov-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  padding: 14px;
}
@media (max-width: 700px) {
  .ad-cov-grid { grid-template-columns: 1fr; }
}
.ad-cov-tile {
  background: var(--tc-input);
  border: 1px solid var(--tc-border);
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.ad-cov-tile-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.ad-cov-label {
  font-size: 11px;
  font-weight: 700;
  color: var(--tc-text);
}
.ad-cov-badge {
  font-size: 9px;
  font-weight: 700;
  padding: 2px 7px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-cov-detail {
  font-size: 10px;
  color: var(--tc-text-sec);
  line-height: 1.45;
}
.ad-cov-meta {
  font-size: 9px;
  color: var(--tc-text-muted);
  font-family: ui-monospace, 'JetBrains Mono', monospace;
}
.ad-cov-action {
  font-size: 10px;
  color: #d09020;
  font-style: italic;
  margin-top: 2px;
}
.ad-loading,
.ad-error {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 60px 20px;
  font-size: 12px;
  background: var(--tc-surface);
  border: 1px solid var(--tc-border);
  margin-bottom: 14px;
}
.ad-loading { color: var(--tc-text-muted); }
.ad-error { color: #ff4040; }
.ad-spin { animation: ad-spin 1s linear infinite; }
@keyframes ad-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
`;

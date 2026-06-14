"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { PageShell } from "@/components/chrome/PageShell";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { ArrowLeft, Activity, Server, AlertCircle, RefreshCw, Tag as TagIcon, Search } from "lucide-react";

type RecentAlert = {
  matched_at: string | null;
  level: string | null;
  hostname: string | null;
  source_ip: string | null;
  username: string | null;
  status: string | null;
};

type RuleDetail = {
  id: string;
  title: string;
  description: string | null;
  level: string;
  status: string | null;
  enabled: boolean;
  logsource_category: string | null;
  logsource_product: string | null;
  logsource_service: string | null;
  tags: string[];
  author: string | null;
  rule_yaml: string | null;
  detection_json: unknown;
  updated_at: string | null;
  fire_count_7d: number;
  fire_count_30d: number;
  last_fire_at: string | null;
  fp_count_7d: number;
  distinct_hosts_7d: number;
  top_hostname_7d: string | null;
  recent_alerts: RecentAlert[];
  top_hostnames_7d: { hostname: string; count: number }[];
};

const LEVEL_COLOR: Record<string, { color: string; bg: string }> = {
  critical: { color: "#e84040", bg: "rgba(232,64,64,0.10)" },
  high:     { color: "#d07020", bg: "rgba(208,112,32,0.10)" },
  medium:   { color: "#d09020", bg: "rgba(208,144,32,0.10)" },
  low:      { color: "#3080d0", bg: "rgba(48,128,208,0.10)" },
  informational: { color: "var(--tc-text-muted)", bg: "var(--tc-input)" },
};

export default function SigmaRuleDetailPage() {
  const router = useRouter();
  const locale = useLocale();
  const params = useParams();
  const ruleId = params?.ruleId as string;

  const labels = useMemo(() => ({
    back:      locale === "fr" ? "Règles" : "Rules",
    refresh:   locale === "fr" ? "Actualiser" : "Refresh",
    loading:   locale === "fr" ? "Chargement..." : "Loading...",
    notFound:  locale === "fr" ? "Règle introuvable" : "Rule not found",
    yaml:      locale === "fr" ? "Règle (YAML)" : "Rule (YAML)",
    detection: locale === "fr" ? "Détection compilée" : "Compiled detection",
    metadata:  locale === "fr" ? "Métadonnées" : "Metadata",
    activity:  locale === "fr" ? "Activité 7 jours" : "7-day activity",
    fire7:     locale === "fr" ? "Matches 7j" : "Matches 7d",
    fire30:    locale === "fr" ? "Matches 30j" : "Matches 30d",
    fp:        locale === "fr" ? "Faux positifs 7j" : "False positives 7d",
    hosts:     locale === "fr" ? "Hôtes distincts 7j" : "Distinct hosts 7d",
    lastFire:  locale === "fr" ? "Dernier match" : "Last fire",
    topHosts:  locale === "fr" ? "Top hôtes (7j)" : "Top hosts (7d)",
    recent:    locale === "fr" ? "Alertes récentes" : "Recent alerts",
    noRecent:  locale === "fr" ? "Aucune alerte récente." : "No recent alerts.",
    never:     locale === "fr" ? "Jamais" : "Never",
    source:    locale === "fr" ? "Source" : "Source",
    level:     locale === "fr" ? "Sévérité" : "Severity",
    status:    locale === "fr" ? "Statut" : "Status",
    author:    locale === "fr" ? "Auteur" : "Author",
    updated:   locale === "fr" ? "Mis à jour" : "Updated",
    tags:      locale === "fr" ? "Tags" : "Tags",
    hunt:      locale === "fr" ? "Voir les logs" : "View logs",
    enabled:   locale === "fr" ? "Active" : "Enabled",
    disabled:  locale === "fr" ? "Désactivée" : "Disabled",
  }), [locale]);

  const [data, setData] = useState<RuleDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!ruleId) return;
    setError(null);
    try {
      const res = await fetch(`/api/tc/sigma/rules/${encodeURIComponent(ruleId)}`);
      if (res.status === 404) {
        setError(labels.notFound);
        setLoading(false);
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: RuleDetail = await res.json();
      setData(json);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [ruleId, labels.notFound]);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return (
      <PageShell title={labels.loading}>
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.loading}</div></NeuCard>
      </PageShell>
    );
  }

  if (error || !data) {
    return (
      <PageShell title={labels.notFound}>
        <ErrorBanner message={error || labels.notFound} onRetry={load} />
        <ChromeButton onClick={() => router.push("/sigma")} variant="glass">
          <ArrowLeft size={13} /> {labels.back}
        </ChromeButton>
      </PageShell>
    );
  }

  const lvlColors = LEVEL_COLOR[data.level] || LEVEL_COLOR.informational;
  const huntHref = `/hunt?from=${encodeURIComponent(new Date(Date.now() - 24 * 60 * 60_000).toISOString())}&q=${encodeURIComponent(data.id)}`;

  return (
    <PageShell
      title={data.title}
      subtitle={data.id}
      right={
        <div style={{ display: "flex", gap: "6px" }}>
          <ChromeButton onClick={() => router.push("/sigma")} variant="glass">
            <ArrowLeft size={13} /> {labels.back}
          </ChromeButton>
          <ChromeButton onClick={() => router.push(huntHref)} variant="glass">
            <Search size={13} /> {labels.hunt}
          </ChromeButton>
          <ChromeButton onClick={load} variant="glass">
            <RefreshCw size={13} />
          </ChromeButton>
        </div>
      }
    >
      {/* Activity strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
        gap: "8px", marginBottom: "16px" }}>
        <Metric label={labels.fire7} value={data.fire_count_7d} icon={<Activity size={12} />}
          accent={data.fire_count_7d >= 50 ? "#d07020" : data.fire_count_7d > 0 ? "var(--tc-text)" : "var(--tc-text-muted)"} />
        <Metric label={labels.fire30} value={data.fire_count_30d} />
        <Metric label={labels.fp} value={data.fp_count_7d} icon={<AlertCircle size={12} />}
          accent={data.fp_count_7d > 0 ? "var(--tc-amber)" : "var(--tc-text-muted)"} />
        <Metric label={labels.hosts} value={data.distinct_hosts_7d} icon={<Server size={12} />} />
        <Metric label={labels.lastFire}
          valueLabel={data.last_fire_at
            ? new Date(data.last_fire_at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US")
            : labels.never}
          accent={data.last_fire_at ? "var(--tc-text)" : "var(--tc-text-muted)"} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: "16px", alignItems: "flex-start" }}>
        {/* Left column — YAML + metadata + recent alerts */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Metadata strip */}
          <NeuCard style={{ padding: "16px" }}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "16px 28px", alignItems: "flex-start" }}>
              <Field label={labels.level}>
                <span style={{
                  display: "inline-block", padding: "2px 10px", borderRadius: "var(--tc-radius-sm)",
                  background: lvlColors.bg, color: lvlColors.color,
                  fontSize: "11px", fontWeight: 700, textTransform: "uppercase",
                }}>{data.level}</span>
              </Field>
              <Field label={labels.source}>
                <span style={{ fontFamily: "monospace", color: "var(--tc-text)" }}>
                  {[data.logsource_category, data.logsource_product, data.logsource_service].filter(Boolean).join(" / ") || "—"}
                </span>
              </Field>
              <Field label={labels.status}>
                <span style={{ color: "var(--tc-text)" }}>{data.status || "—"}</span>
              </Field>
              <Field label={data.enabled ? labels.enabled : labels.disabled}>
                <span style={{
                  width: "10px", height: "10px", borderRadius: "50%", display: "inline-block",
                  background: data.enabled ? "#30a050" : "var(--tc-text-muted)",
                }} />
              </Field>
              {data.author && <Field label={labels.author}><span style={{ color: "var(--tc-text)" }}>{data.author}</span></Field>}
              {data.updated_at && (
                <Field label={labels.updated}>
                  <span style={{ color: "var(--tc-text-muted)", fontSize: "11px" }}>
                    {new Date(data.updated_at).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US")}
                  </span>
                </Field>
              )}
            </div>

            {data.description && (
              <div style={{ marginTop: "14px", paddingTop: "12px", borderTop: "1px solid var(--tc-border-light)",
                color: "var(--tc-text-sec)", fontSize: "13px", lineHeight: 1.5 }}>
                {data.description}
              </div>
            )}

            {data.tags && data.tags.length > 0 && (
              <div style={{ marginTop: "12px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
                {data.tags.map(t => (
                  <span key={t} style={{
                    fontSize: "10px", padding: "2px 8px", borderRadius: "var(--tc-radius-sm)",
                    background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                    color: "var(--tc-text-muted)", fontFamily: "monospace",
                    display: "inline-flex", alignItems: "center", gap: "4px",
                  }}>
                    <TagIcon size={9} /> {t}
                  </span>
                ))}
              </div>
            )}
          </NeuCard>

          {/* YAML */}
          {data.rule_yaml && (
            <NeuCard style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--tc-border)",
                fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase",
                color: "var(--tc-text-muted)", fontWeight: 600 }}>
                {labels.yaml}
              </div>
              <pre style={{
                margin: 0, padding: "14px", background: "var(--tc-input)",
                fontSize: "11px", lineHeight: 1.6, color: "var(--tc-text)",
                fontFamily: "monospace", overflow: "auto", maxHeight: "420px",
              }}>{data.rule_yaml}</pre>
            </NeuCard>
          )}

          {/* Recent alerts */}
          <NeuCard style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--tc-border)",
              display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase",
                color: "var(--tc-text-muted)", fontWeight: 600 }}>
                {labels.recent}
              </span>
              <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
                {data.recent_alerts.length}
              </span>
            </div>
            {data.recent_alerts.length === 0 ? (
              <div style={{ padding: "24px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "12px" }}>
                {labels.noRecent}
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                <tbody>
                  {data.recent_alerts.map((a, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid var(--tc-border-light)" }}>
                      <td style={{ padding: "6px 10px", color: "var(--tc-text-muted)",
                        fontFamily: "monospace", whiteSpace: "nowrap", fontSize: "11px" }}>
                        {a.matched_at ? new Date(a.matched_at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US") : "—"}
                      </td>
                      <td style={{ padding: "6px 10px", color: "var(--tc-blue)", fontFamily: "monospace" }}>
                        {a.hostname || "—"}
                      </td>
                      <td style={{ padding: "6px 10px", color: "var(--tc-text-muted)", fontFamily: "monospace", fontSize: "11px" }}>
                        {a.source_ip || ""}
                      </td>
                      <td style={{ padding: "6px 10px", color: "var(--tc-text-muted)", fontSize: "11px" }}>
                        {a.username || ""}
                      </td>
                      <td style={{ padding: "6px 10px", color: a.status === "false_positive" ? "var(--tc-amber)"
                        : a.status === "resolved" ? "#30a050" : "var(--tc-text-muted)",
                        fontSize: "10px", textTransform: "uppercase" }}>
                        {a.status || ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </NeuCard>
        </div>

        {/* Right column — top hosts */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <NeuCard style={{ padding: "16px" }}>
            <div style={{ fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase",
              color: "var(--tc-text-muted)", fontWeight: 600, marginBottom: "12px" }}>
              {labels.topHosts}
            </div>
            {data.top_hostnames_7d.length === 0 ? (
              <div style={{ color: "var(--tc-text-muted)", fontSize: "12px" }}>—</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                {data.top_hostnames_7d.map((h, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
                    padding: "6px 8px", background: "var(--tc-surface-alt)",
                    borderRadius: "var(--tc-radius-sm)", fontSize: "12px" }}>
                    <span style={{ fontFamily: "monospace", color: "var(--tc-blue)" }}>{h.hostname}</span>
                    <span style={{ fontFamily: "monospace", fontWeight: 700, color: "var(--tc-text)" }}>{h.count}</span>
                  </div>
                ))}
              </div>
            )}
          </NeuCard>
        </div>
      </div>
    </PageShell>
  );
}

function Metric({ label, value, valueLabel, accent, icon }: {
  label: string; value?: number; valueLabel?: string; accent?: string; icon?: React.ReactNode;
}) {
  return (
    <NeuCard style={{ padding: "12px 14px" }}>
      <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "var(--tc-text-muted)",
        textTransform: "uppercase", marginBottom: "4px", display: "flex", alignItems: "center", gap: "5px" }}>
        {icon} {label}
      </div>
      <div style={{ fontSize: valueLabel ? "13px" : "22px", fontWeight: 700,
        color: accent || "var(--tc-text)", fontFamily: valueLabel ? "inherit" : "monospace" }}>
        {valueLabel ?? value}
      </div>
    </NeuCard>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
      <span style={{ fontSize: "9px", letterSpacing: "0.12em", textTransform: "uppercase",
        color: "var(--tc-text-muted)", fontWeight: 600 }}>{label}</span>
      <div style={{ fontSize: "13px" }}>{children}</div>
    </div>
  );
}

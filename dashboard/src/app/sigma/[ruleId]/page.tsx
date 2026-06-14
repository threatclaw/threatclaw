"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { PageShell } from "@/components/chrome/PageShell";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { ArrowLeft, Activity, Server, AlertCircle, RefreshCw, Tag as TagIcon, Search,
  Power, Sliders, Plus, Trash2, ShieldOff } from "lucide-react";

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
  disposition: string;
  tier: string;
  promoted_at: string | null;
};

type Exception = {
  id: number;
  rule_id: string;
  scope_field: string;
  scope_value: string;
  reason: string | null;
  owner: string | null;
  created_at: string | null;
  expires_at: string | null;
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
    tuning:    locale === "fr" ? "Tuning" : "Tuning",
    enable:    locale === "fr" ? "Activer" : "Enable",
    disable:   locale === "fr" ? "Désactiver" : "Disable",
    disposition: locale === "fr" ? "Disposition" : "Disposition",
    tier:      locale === "fr" ? "Sphère" : "Tier",
    statusL:   locale === "fr" ? "Lifecycle" : "Lifecycle",
    monitor:   locale === "fr" ? "Audit seul" : "Monitor",
    detectD:   locale === "fr" ? "Détecter" : "Detect",
    block:     locale === "fr" ? "Bloquer (HITL)" : "Block (HITL)",
    page:      locale === "fr" ? "Page" : "Page",
    queue:     locale === "fr" ? "Queue" : "Queue",
    rba:       locale === "fr" ? "RBA seul" : "RBA-only",
    expL:      locale === "fr" ? "Expérimental" : "Experimental",
    test:      locale === "fr" ? "Test" : "Test",
    stable:    locale === "fr" ? "Stable" : "Stable",
    deprecated:locale === "fr" ? "Déprécié" : "Deprecated",
    exceptions:locale === "fr" ? "Exceptions" : "Exceptions",
    addExc:    locale === "fr" ? "Ajouter une exception" : "Add exception",
    noExc:     locale === "fr" ? "Aucune exception active." : "No active exception.",
    excScope:  locale === "fr" ? "Critère" : "Scope",
    excValue:  locale === "fr" ? "Valeur" : "Value",
    excReason: locale === "fr" ? "Raison" : "Reason",
    excOwner:  locale === "fr" ? "Propriétaire" : "Owner",
    excExpires:locale === "fr" ? "Expire dans (jours, 0 = jamais)" : "Expires in (days, 0 = never)",
    excHost:   locale === "fr" ? "Hostname" : "Hostname",
    excIp:     locale === "fr" ? "IP source" : "Source IP",
    excUser:   locale === "fr" ? "Utilisateur" : "Username",
    excTag:    locale === "fr" ? "Tag" : "Tag",
    save:      locale === "fr" ? "Enregistrer" : "Save",
    cancel:    locale === "fr" ? "Annuler" : "Cancel",
  }), [locale]);

  const [data, setData] = useState<RuleDetail | null>(null);
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!ruleId) return;
    setError(null);
    try {
      const [ruleRes, excRes] = await Promise.all([
        fetch(`/api/tc/sigma/rules/${encodeURIComponent(ruleId)}`),
        fetch(`/api/tc/sigma/rules/${encodeURIComponent(ruleId)}/exceptions`),
      ]);
      if (ruleRes.status === 404) {
        setError(labels.notFound);
        setLoading(false);
        return;
      }
      if (!ruleRes.ok) throw new Error(`HTTP ${ruleRes.status}`);
      const json: RuleDetail = await ruleRes.json();
      setData(json);
      if (excRes.ok) {
        const excJson = await excRes.json();
        setExceptions(Array.isArray(excJson.items) ? excJson.items : []);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [ruleId, labels.notFound]);

  useEffect(() => { load(); }, [load]);

  const toggleEnabled = async () => {
    if (!data) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/tc/sigma/rules/${encodeURIComponent(data.id)}/enabled`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !data.enabled }),
      });
      if (res.ok) await load();
    } finally {
      setBusy(false);
    }
  };

  const updatePromotion = async (patch: { disposition?: string; tier?: string; status?: string }) => {
    if (!data) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/tc/sigma/rules/${encodeURIComponent(data.id)}/promotion`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (res.ok) await load();
    } finally {
      setBusy(false);
    }
  };

  const addException = async (form: {
    scope_field: string; scope_value: string;
    reason: string; owner: string; expires_in_days: number | null;
  }) => {
    if (!data) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/tc/sigma/rules/${encodeURIComponent(data.id)}/exceptions`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scope_field: form.scope_field,
          scope_value: form.scope_value,
          reason: form.reason || null,
          owner: form.owner || null,
          expires_in_days: form.expires_in_days,
        }),
      });
      if (res.ok) await load();
    } finally {
      setBusy(false);
    }
  };

  const deleteException = async (id: number) => {
    setBusy(true);
    try {
      await fetch(`/api/tc/sigma/exceptions/${id}`, { method: "DELETE" });
      await load();
    } finally {
      setBusy(false);
    }
  };

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

        {/* Right column — tuning + exceptions + top hosts */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Tuning */}
          <NeuCard style={{ padding: "16px" }}>
            <div style={{ fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase",
              color: "var(--tc-text-muted)", fontWeight: 600, marginBottom: "12px",
              display: "flex", alignItems: "center", gap: "6px" }}>
              <Sliders size={12} /> {labels.tuning}
            </div>

            <ChromeButton onClick={toggleEnabled} variant="glass" disabled={busy}
              style={{ width: "100%", marginBottom: "10px" }}>
              <Power size={13} /> {data.enabled ? labels.disable : labels.enable}
            </ChromeButton>

            <SmallSelect label={labels.disposition} value={data.disposition}
              disabled={busy}
              onChange={v => updatePromotion({ disposition: v })}
              options={[
                { value: "monitor", label: labels.monitor },
                { value: "detect", label: labels.detectD },
                { value: "block", label: labels.block },
              ]} />

            <SmallSelect label={labels.tier} value={data.tier}
              disabled={busy}
              onChange={v => updatePromotion({ tier: v })}
              options={[
                { value: "queue", label: labels.queue },
                { value: "page", label: labels.page },
                { value: "rba_only", label: labels.rba },
              ]} />

            <SmallSelect label={labels.statusL} value={data.status || "experimental"}
              disabled={busy}
              onChange={v => updatePromotion({ status: v })}
              options={[
                { value: "experimental", label: labels.expL },
                { value: "test", label: labels.test },
                { value: "stable", label: labels.stable },
                { value: "deprecated", label: labels.deprecated },
              ]} />
          </NeuCard>

          {/* Exceptions */}
          <NeuCard style={{ padding: "16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
              <div style={{ fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase",
                color: "var(--tc-text-muted)", fontWeight: 600,
                display: "flex", alignItems: "center", gap: "6px" }}>
                <ShieldOff size={12} /> {labels.exceptions}
                {exceptions.length > 0 && (
                  <span style={{ color: "var(--tc-text)", fontWeight: 700 }}> · {exceptions.length}</span>
                )}
              </div>
            </div>

            <ExceptionForm labels={labels} onAdd={addException} busy={busy} />

            {exceptions.length === 0 ? (
              <div style={{ marginTop: "10px", color: "var(--tc-text-muted)", fontSize: "11px" }}>{labels.noExc}</div>
            ) : (
              <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "6px" }}>
                {exceptions.map(e => (
                  <div key={e.id} style={{
                    padding: "8px 10px", background: "var(--tc-surface-alt)",
                    borderRadius: "var(--tc-radius-sm)", fontSize: "11px",
                    display: "flex", flexDirection: "column", gap: "4px",
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontFamily: "monospace", color: "var(--tc-text)" }}>
                        <span style={{ color: "var(--tc-text-muted)" }}>{e.scope_field} =</span> {e.scope_value}
                      </span>
                      <button onClick={() => deleteException(e.id)}
                        disabled={busy}
                        style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: 0 }}>
                        <Trash2 size={11} />
                      </button>
                    </div>
                    {(e.reason || e.owner) && (
                      <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
                        {e.reason} {e.owner && `· ${e.owner}`}
                      </div>
                    )}
                    {e.expires_at && (
                      <div style={{ fontSize: "10px", color: "var(--tc-amber)" }}>
                        ⤳ {new Date(e.expires_at).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US")}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </NeuCard>

          {/* Top hosts */}
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

function SmallSelect({ label, value, onChange, options, disabled }: {
  label: string; value: string; onChange: (v: string) => void;
  options: { value: string; label: string }[]; disabled?: boolean;
}) {
  return (
    <div style={{ marginBottom: "10px" }}>
      <div style={{ fontSize: "9px", letterSpacing: "0.12em", textTransform: "uppercase",
        color: "var(--tc-text-muted)", fontWeight: 600, marginBottom: "4px" }}>
        {label}
      </div>
      <select value={value} disabled={disabled} onChange={e => onChange(e.target.value)}
        style={{ width: "100%", padding: "6px 10px",
          background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)",
          fontSize: "12px", fontFamily: "inherit", outline: "none" }}>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

function ExceptionForm({ labels, onAdd, busy }: {
  labels: Record<string, string>;
  onAdd: (f: { scope_field: string; scope_value: string; reason: string; owner: string; expires_in_days: number | null }) => void;
  busy: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState("hostname");
  const [val, setVal] = useState("");
  const [reason, setReason] = useState("");
  const [owner, setOwner] = useState("");
  const [days, setDays] = useState("30");

  if (!open) {
    return (
      <ChromeButton onClick={() => setOpen(true)} variant="glass" disabled={busy} style={{ width: "100%" }}>
        <Plus size={12} /> {labels.addExc}
      </ChromeButton>
    );
  }

  const submit = () => {
    if (!val.trim()) return;
    const d = parseInt(days, 10);
    onAdd({
      scope_field: scope,
      scope_value: val.trim(),
      reason: reason.trim(),
      owner: owner.trim(),
      expires_in_days: Number.isFinite(d) && d > 0 ? d : null,
    });
    setVal(""); setReason(""); setOwner(""); setDays("30");
    setOpen(false);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px", padding: "10px",
      background: "var(--tc-surface-alt)", borderRadius: "var(--tc-radius-sm)" }}>
      <select value={scope} onChange={e => setScope(e.target.value)}
        style={{ padding: "6px 10px", background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)", fontSize: "11px", fontFamily: "inherit" }}>
        <option value="hostname">{labels.excHost}</option>
        <option value="source_ip">{labels.excIp}</option>
        <option value="username">{labels.excUser}</option>
        <option value="tag">{labels.excTag}</option>
      </select>
      <input value={val} onChange={e => setVal(e.target.value)} placeholder={labels.excValue}
        style={inputStyle()} />
      <input value={reason} onChange={e => setReason(e.target.value)} placeholder={labels.excReason}
        style={inputStyle()} />
      <input value={owner} onChange={e => setOwner(e.target.value)} placeholder={labels.excOwner}
        style={inputStyle()} />
      <input value={days} onChange={e => setDays(e.target.value)} type="number"
        placeholder={labels.excExpires} style={inputStyle()} />
      <div style={{ display: "flex", gap: "6px" }}>
        <ChromeButton onClick={submit} variant="primary" disabled={busy || !val.trim()} style={{ flex: 1 }}>
          {labels.save}
        </ChromeButton>
        <ChromeButton onClick={() => setOpen(false)} variant="glass" disabled={busy}>
          {labels.cancel}
        </ChromeButton>
      </div>
    </div>
  );
}

function inputStyle(): React.CSSProperties {
  return {
    padding: "6px 10px", background: "var(--tc-input)", border: "1px solid var(--tc-border)",
    borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)",
    fontSize: "11px", fontFamily: "inherit", outline: "none", boxSizing: "border-box",
  };
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

"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { PageShell } from "@/components/chrome/PageShell";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { ArrowLeft, RefreshCw, ShieldOff, Trash2, Clock } from "lucide-react";

type Exception = {
  id: number;
  rule_id: string;
  rule_title: string;
  scope_field: string;
  scope_value: string;
  reason: string | null;
  owner: string | null;
  created_at: string | null;
  expires_at: string | null;
};

export default function SigmaAuditPage() {
  const router = useRouter();
  const locale = useLocale();
  const labels = useMemo(() => ({
    title:     locale === "fr" ? "Audit du tuning Sigma" : "Sigma tuning audit",
    subtitle:  locale === "fr"
      ? "Vue d'ensemble des exceptions actives. Une exception silencie une règle pour un hôte / IP / utilisateur / tag, avec ou sans expiration."
      : "Overview of active exceptions. Each one silences a rule for a host / IP / user / tag, with or without an expiry.",
    back:      locale === "fr" ? "Règles" : "Rules",
    refresh:   locale === "fr" ? "Actualiser" : "Refresh",
    loading:   locale === "fr" ? "Chargement..." : "Loading...",
    none:      locale === "fr" ? "Aucune exception active." : "No active exception.",
    total:     locale === "fr" ? "exceptions actives" : "active exceptions",
    expiring:  locale === "fr" ? "expirent dans 7j" : "expiring in 7d",
    perm:      locale === "fr" ? "permanentes" : "permanent",
    rule:      locale === "fr" ? "Règle" : "Rule",
    scope:     locale === "fr" ? "Critère" : "Scope",
    value:     locale === "fr" ? "Valeur" : "Value",
    reason:    locale === "fr" ? "Raison" : "Reason",
    owner:     locale === "fr" ? "Propriétaire" : "Owner",
    created:   locale === "fr" ? "Créée" : "Created",
    expires:   locale === "fr" ? "Expiration" : "Expires",
    never:     locale === "fr" ? "jamais" : "never",
    delete:    locale === "fr" ? "Supprimer" : "Delete",
  }), [locale]);

  const [items, setItems] = useState<Exception[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch("/api/tc/sigma/audit");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setItems(Array.isArray(json.exceptions) ? json.exceptions : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const remove = async (id: number) => {
    setBusy(true);
    try {
      await fetch(`/api/tc/sigma/exceptions/${id}`, { method: "DELETE" });
      await load();
    } finally {
      setBusy(false);
    }
  };

  const counters = useMemo(() => {
    const now = Date.now();
    const week = 7 * 24 * 60 * 60_000;
    return {
      total: items.length,
      expiring: items.filter(e => e.expires_at && new Date(e.expires_at).getTime() - now < week).length,
      perm: items.filter(e => !e.expires_at).length,
    };
  }, [items]);

  return (
    <PageShell title={labels.title} subtitle={labels.subtitle}
      right={
        <div style={{ display: "flex", gap: "6px" }}>
          <ChromeButton onClick={() => router.push("/sigma")} variant="glass">
            <ArrowLeft size={13} /> {labels.back}
          </ChromeButton>
          <ChromeButton onClick={load} variant="glass">
            <RefreshCw size={13} />
          </ChromeButton>
        </div>
      }>
      {error && <ErrorBanner message={error} onRetry={load} />}

      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        <Pill label={labels.total} value={counters.total} icon={<ShieldOff size={11} />} />
        <Pill label={labels.expiring} value={counters.expiring} color="var(--tc-amber)" icon={<Clock size={11} />} />
        <Pill label={labels.perm} value={counters.perm} color="var(--tc-text-muted)" />
      </div>

      {loading ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.loading}</div></NeuCard>
      ) : items.length === 0 ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.none}</div></NeuCard>
      ) : (
        <NeuCard style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", borderBottom: "1px solid var(--tc-border)" }}>
                <Th>{labels.rule}</Th>
                <Th>{labels.scope}</Th>
                <Th>{labels.value}</Th>
                <Th>{labels.reason}</Th>
                <Th>{labels.owner}</Th>
                <Th>{labels.created}</Th>
                <Th>{labels.expires}</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {items.map(e => {
                const expiringSoon = e.expires_at &&
                  new Date(e.expires_at).getTime() - Date.now() < 7 * 24 * 60 * 60_000;
                return (
                  <tr key={e.id} style={{ borderBottom: "1px solid var(--tc-border-light)" }}>
                    <td style={tdStyle()}
                      onClick={() => router.push(`/sigma/${encodeURIComponent(e.rule_id)}`)}>
                      <div style={{ cursor: "pointer" }}>
                        <div style={{ color: "var(--tc-text)" }}>{e.rule_title}</div>
                        <div style={{ fontFamily: "monospace", fontSize: "10px", color: "var(--tc-text-muted)" }}>{e.rule_id}</div>
                      </div>
                    </td>
                    <td style={{ ...tdStyle(), color: "var(--tc-text-muted)", fontFamily: "monospace" }}>{e.scope_field}</td>
                    <td style={{ ...tdStyle(), fontFamily: "monospace", color: "var(--tc-blue)" }}>{e.scope_value}</td>
                    <td style={{ ...tdStyle(), color: "var(--tc-text-sec)" }}>{e.reason || "—"}</td>
                    <td style={{ ...tdStyle(), color: "var(--tc-text-muted)" }}>{e.owner || "—"}</td>
                    <td style={{ ...tdStyle(), color: "var(--tc-text-muted)", fontSize: "11px", whiteSpace: "nowrap" }}>
                      {e.created_at ? new Date(e.created_at).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US") : "—"}
                    </td>
                    <td style={{ ...tdStyle(), color: expiringSoon ? "var(--tc-amber)" : "var(--tc-text-muted)",
                      fontSize: "11px", whiteSpace: "nowrap" }}>
                      {e.expires_at
                        ? new Date(e.expires_at).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US")
                        : labels.never}
                    </td>
                    <td style={{ ...tdStyle(), textAlign: "right" }}>
                      <button onClick={() => remove(e.id)} disabled={busy}
                        style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px" }}
                        title={labels.delete}>
                        <Trash2 size={13} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </NeuCard>
      )}
    </PageShell>
  );
}

function Th({ children }: { children?: React.ReactNode }) {
  return (
    <th style={{ padding: "8px 12px", textAlign: "left", fontSize: "10px",
      letterSpacing: "0.12em", textTransform: "uppercase",
      color: "var(--tc-text-muted)", fontWeight: 600 }}>
      {children}
    </th>
  );
}

function tdStyle(): React.CSSProperties {
  return { padding: "10px 12px", fontSize: "12px" };
}

function Pill({ label, value, color, icon }: {
  label: string; value: number; color?: string; icon?: React.ReactNode;
}) {
  return (
    <div style={{
      padding: "8px 14px", borderRadius: "var(--tc-radius-md)",
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-input)",
      display: "flex", alignItems: "center", gap: "8px", fontSize: "12px",
    }}>
      {icon && <span style={{ color: color || "var(--tc-text-muted)" }}>{icon}</span>}
      <span style={{ fontWeight: 800, fontSize: "16px", color: color || "var(--tc-text)", fontFamily: "monospace" }}>{value}</span>
      <span style={{ color: "var(--tc-text-muted)", textTransform: "uppercase", fontSize: "10px", letterSpacing: "0.08em" }}>{label}</span>
    </div>
  );
}

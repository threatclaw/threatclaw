"use client";

import { useEffect, useState } from "react";
import type { EvidenceCitation } from "@/app/incidents/page";

interface IncidentLite {
  id: number;
  asset: string;
  title: string;
  severity: string | null;
  mitre_techniques: string[] | null;
  proposed_actions?: { actions?: unknown[]; iocs?: string[] } | null | any;
  evidence_citations?: EvidenceCitation[];
}

interface Props {
  incident: IncidentLite;
  locale: string;
  onClose: () => void;
  onCreated?: (ruleId: string) => void;
}

interface PreviewResult {
  candidates_total: number;
  matched: number;
  confirmed_matches: number;
  eval_errors: number;
  lookback_days: number;
  warning: string | null;
  sample: Array<{
    id: number;
    asset: string;
    title: string;
    verdict: string;
    severity: string | null;
    created_at: string;
  }>;
}

type Action = "drop" | "downgrade" | "tag";

/**
 * Pre-fill CEL from incident metadata. See ADR-047.
 * Kept simple on purpose — RSSI can refine manually after preview.
 */
function defaultPredicate(i: IncidentLite): string {
  const mitre = i.mitre_techniques ?? [];
  const clauses: string[] = [];
  clauses.push(`event.asset == "${i.asset}"`);
  if (mitre.length > 0) {
    const first = mitre[0];
    clauses.push(`"${first}" in event.mitre_techniques`);
  }
  if (i.severity) {
    clauses.push(`event.severity == "${i.severity}"`);
  }
  return clauses.join(" && ");
}

function defaultReason(i: IncidentLite, locale: string): string {
  const fr = locale === "fr";
  return fr
    ? `Pattern récurrent sur ${i.asset} (incident #${i.id}). À confirmer après preview.`
    : `Recurring pattern on ${i.asset} (incident #${i.id}). Confirm after preview.`;
}

export default function SuppressionWizard({ incident, locale, onClose, onCreated }: Props) {
  const fr = locale === "fr";
  const [name, setName] = useState<string>(() =>
    fr ? `Ignorer pattern ${incident.asset}` : `Ignore pattern ${incident.asset}`,
  );
  const [predicate, setPredicate] = useState<string>(() => defaultPredicate(incident));
  const [action, setAction] = useState<Action>("drop");
  const [severityCap, setSeverityCap] = useState<string>("LOW");
  const [reason, setReason] = useState<string>(() => defaultReason(incident, locale));
  const [ttlDays, setTtlDays] = useState<number>(90);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-preview on mount.
  useEffect(() => {
    void runPreview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runPreview() {
    setPreviewing(true);
    setError(null);
    try {
      const res = await fetch("/api/tc/suppression-rules-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          predicate_source: predicate,
          lookback_days: 14,
        }),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`HTTP ${res.status}: ${txt}`);
      }
      setPreview((await res.json()) as PreviewResult);
    } catch (e: any) {
      setError(e?.message ?? String(e));
      setPreview(null);
    } finally {
      setPreviewing(false);
    }
  }

  async function createRule() {
    if (reason.trim().length < 10) {
      setError(fr ? "La raison doit faire au moins 10 caractères" : "Reason must be at least 10 characters");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const expires = new Date(Date.now() + ttlDays * 86_400_000).toISOString();
      const res = await fetch("/api/tc/suppression-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          predicate_source: predicate,
          action,
          severity_cap: action === "downgrade" ? severityCap : null,
          scope: "global",
          reason,
          expires_at: expires,
          created_by: "dashboard",
          source: "manual",
        }),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`HTTP ${res.status}: ${txt}`);
      }
      const { id } = await res.json();
      onCreated?.(id);
      onClose();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setCreating(false);
    }
  }

  const reasonValid = reason.trim().length >= 10;
  const predicateValid = predicate.trim().length > 0;

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.65)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(720px, 92vw)",
          maxHeight: "90vh",
          overflowY: "auto",
          background: "var(--tc-surface)",
          color: "var(--tc-text-pri)",
          border: "1px solid var(--tc-border)",
          borderRadius: 12,
          padding: 24,
          boxShadow: "0 24px 60px rgba(0,0,0,0.55)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>
            {fr ? "Créer une règle de suppression" : "Create suppression rule"}
          </h2>
          <button
            onClick={onClose}
            style={{ background: "none", border: "none", color: "var(--tc-text-sec)", fontSize: 18, cursor: "pointer" }}
            aria-label={fr ? "Fermer" : "Close"}
          >
            ✕
          </button>
        </div>

        <div style={{ fontSize: 11, color: "var(--tc-text-sec)", marginBottom: 14 }}>
          {fr ? "Basé sur l'incident #" : "Based on incident #"}{incident.id} · {incident.title}
        </div>

        {/* Name */}
        <Field label={fr ? "Nom de la règle" : "Rule name"}>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={inputStyle}
          />
        </Field>

        {/* Predicate (CEL) */}
        <Field
          label={fr ? "Prédicat CEL" : "CEL predicate"}
          hint={fr
            ? "Expression qui évalue à true = suppression. Variables: event.*"
            : "Expression evaluating to true = suppress. Variables: event.*"}
        >
          <textarea
            value={predicate}
            onChange={(e) => setPredicate(e.target.value)}
            rows={3}
            style={{ ...inputStyle, fontFamily: "monospace", fontSize: 11 }}
          />
        </Field>

        {/* Action + TTL */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <Field label={fr ? "Action" : "Action"}>
            <select value={action} onChange={(e) => setAction(e.target.value as Action)} style={inputStyle}>
              <option value="drop">{fr ? "Ignorer (drop)" : "Drop"}</option>
              <option value="downgrade">{fr ? "Réduire sévérité" : "Downgrade"}</option>
              <option value="tag">{fr ? "Tagger seulement" : "Tag only"}</option>
            </select>
          </Field>
          <Field label={fr ? "Expiration (jours)" : "Expires in (days)"}>
            <input
              type="number"
              value={ttlDays}
              min={1}
              max={730}
              onChange={(e) => setTtlDays(Number(e.target.value) || 90)}
              style={inputStyle}
            />
          </Field>
        </div>

        {action === "downgrade" && (
          <Field label={fr ? "Plafond de sévérité" : "Severity cap"}>
            <select value={severityCap} onChange={(e) => setSeverityCap(e.target.value)} style={inputStyle}>
              <option value="INFO">INFO</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
            </select>
          </Field>
        )}

        {/* Reason (mandatory ≥10) */}
        <Field
          label={fr ? "Raison (obligatoire, ≥ 10 car.)" : "Reason (required, ≥ 10 chars)"}
          hint={fr
            ? "Sera inclue dans l'audit trail NIS2"
            : "Will be recorded in the NIS2 audit trail"}
          error={!reasonValid && reason.length > 0
            ? (fr ? `Manque ${10 - reason.length} caractère(s)` : `Needs ${10 - reason.length} more char(s)`)
            : undefined}
        >
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
            style={inputStyle}
          />
        </Field>

        {/* Preview */}
        <div
          style={{
            marginTop: 12,
            padding: 12,
            borderRadius: 8,
            background: "var(--tc-bg-elevated)",
            border: "1px solid var(--tc-border)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--tc-text-sec)" }}>
              {fr ? "Aperçu sur 14 jours" : "14-day preview"}
            </div>
            <button
              onClick={runPreview}
              disabled={previewing || !predicateValid}
              style={{
                fontSize: 10,
                padding: "4px 10px",
                borderRadius: 4,
                border: "1px solid var(--tc-border)",
                background: "transparent",
                color: "var(--tc-text-sec)",
                cursor: previewing ? "wait" : "pointer",
              }}
            >
              {previewing ? (fr ? "Calcul..." : "Running...") : (fr ? "🔄 Relancer" : "🔄 Re-run")}
            </button>
          </div>
          {preview ? (
            <div style={{ fontSize: 12 }}>
              <div>
                {fr
                  ? `Cette règle aurait supprimé ${preview.matched} incident(s) sur ${preview.candidates_total}.`
                  : `This rule would have suppressed ${preview.matched} out of ${preview.candidates_total} incidents.`}
              </div>
              {preview.confirmed_matches > 0 && (
                <div style={{ color: "#ff4040", marginTop: 6, fontWeight: 500 }}>
                  ⚠️ {fr
                    ? `${preview.confirmed_matches} incident(s) CONFIRMÉS seraient supprimés — règle probablement trop large.`
                    : `${preview.confirmed_matches} CONFIRMED incident(s) would be suppressed — rule likely too broad.`}
                </div>
              )}
              {preview.eval_errors > 0 && (
                <div style={{ color: "#e0a020", marginTop: 4, fontSize: 11 }}>
                  {fr
                    ? `${preview.eval_errors} erreur(s) d'évaluation (champs manquants). Non-bloquant.`
                    : `${preview.eval_errors} eval error(s) (missing fields). Non-blocking.`}
                </div>
              )}
              {preview.sample.length > 0 && (
                <details style={{ marginTop: 8, fontSize: 11, color: "var(--tc-text-sec)" }}>
                  <summary style={{ cursor: "pointer" }}>
                    {fr ? "Voir quelques incidents concernés" : "Sample incidents"} ({preview.sample.length})
                  </summary>
                  <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 3 }}>
                    {preview.sample.map((s) => (
                      <div
                        key={s.id}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "40px 1fr auto",
                          gap: 6,
                          padding: "3px 6px",
                          background: "var(--tc-surface)",
                          borderRadius: 3,
                        }}
                      >
                        <span style={{ color: "var(--tc-text-muted)" }}>#{s.id}</span>
                        <span>{s.title}</span>
                        <span style={{ color: s.verdict === "confirmed" ? "#ff4040" : "var(--tc-text-muted)", fontSize: 10 }}>
                          {s.verdict}
                        </span>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          ) : (
            <div style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
              {previewing ? (fr ? "Calcul en cours..." : "Running preview...") : fr ? "Pas d'aperçu (vérifiez le prédicat)" : "No preview"}
            </div>
          )}
        </div>

        {error && (
          <div style={{ fontSize: 11, color: "#ff6060", marginTop: 10 }}>
            {error}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 20 }}>
          <button
            onClick={onClose}
            style={{
              padding: "8px 16px",
              border: "1px solid var(--tc-border)",
              background: "transparent",
              color: "var(--tc-text-pri)",
              borderRadius: 6,
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            {fr ? "Annuler" : "Cancel"}
          </button>
          <button
            onClick={createRule}
            disabled={!reasonValid || !predicateValid || creating}
            style={{
              padding: "8px 16px",
              border: "none",
              background: reasonValid && predicateValid ? "var(--tc-blue)" : "var(--tc-text-muted)",
              color: "#fff",
              borderRadius: 6,
              fontSize: 12,
              cursor: creating ? "wait" : reasonValid && predicateValid ? "pointer" : "not-allowed",
              fontWeight: 500,
            }}
          >
            {creating ? (fr ? "Création..." : "Creating...") : fr ? "Créer la règle" : "Create rule"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── small style helpers ──

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 10px",
  background: "var(--tc-bg-elevated)",
  color: "var(--tc-text-pri)",
  border: "1px solid var(--tc-border)",
  borderRadius: 6,
  fontSize: 12,
};

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 12 }}>
      <label style={{ display: "block", fontSize: 11, fontWeight: 500, color: "var(--tc-text-sec)", marginBottom: 4 }}>
        {label}
      </label>
      {children}
      {hint && !error && (
        <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginTop: 3 }}>{hint}</div>
      )}
      {error && (
        <div style={{ fontSize: 10, color: "#ff6060", marginTop: 3 }}>{error}</div>
      )}
    </div>
  );
}

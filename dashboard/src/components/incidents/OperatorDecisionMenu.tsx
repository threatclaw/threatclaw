"use client";

/**
 * Operator decision menu — v1.0.38.
 *
 * Replaces the historical Archive / FP / Ignore triplet with four
 * explicit actions the operator can pick from, plus an admin-only
 * Delete entry that only appears when the caller passes `adminMode`.
 *
 * Each action opens a small modal:
 *   - Resolve      → confirm only
 *   - FP           → optional sigma exception scope + reason
 *   - Accept Risk  → reason required
 *   - Snooze       → duration picker (1h, 4h, 24h, custom)
 *
 * The component owns its own UI state. It POSTs to the relevant
 * `/api/tc/incidents/{id}/{decision}` endpoint and calls `onDone`
 * on success so the parent can reload.
 */

import { useState } from "react";
import {
  Check,
  X as Cross,
  Shield,
  Clock,
  Trash2,
  ChevronDown,
} from "lucide-react";

export type DecisionKind =
  | "resolve"
  | "false_positive"
  | "accept_risk"
  | "snooze"
  | "delete";

export type ExceptionKind = "asset" | "username" | "source_ip";

interface Props {
  incidentId: number;
  /** Pre-fills the FP exception's rule id when the dashboard already
   *  knows the dominant sigma rule that drove the incident. */
  ruleId?: string | null;
  /** Pre-fills the exception value drop-downs. */
  assetHostname?: string | null;
  username?: string | null;
  sourceIp?: string | null;
  /** Operator label persisted in the audit trail. */
  actor?: string;
  /** When true, the menu also exposes the admin-only Delete entry. */
  adminMode?: boolean;
  /** Layout. `dropdown` (default) renders a single "Decision" button
   *  that toggles a popover — used on dense list views. `inline`
   *  renders each action as a full-width button stacked vertically —
   *  used on the incident detail page where vertical space is cheap
   *  and discoverability matters more than density. */
  variant?: "dropdown" | "inline";
  /** Called after a successful POST. The parent should re-fetch. */
  onDone?: (decision: DecisionKind) => void;
}

interface ModalState {
  kind: DecisionKind;
}

export function OperatorDecisionMenu(props: Props) {
  const [open, setOpen] = useState(false);
  const [modal, setModal] = useState<ModalState | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // ── Form state shared across modals ────────────────────────────
  const [reason, setReason] = useState("");
  const [exceptionKind, setExceptionKind] = useState<ExceptionKind | "none">(
    "none",
  );
  const [exceptionValue, setExceptionValue] = useState("");
  const [snoozeHours, setSnoozeHours] = useState<number>(4);

  const close = () => {
    setModal(null);
    setReason("");
    setExceptionKind("none");
    setExceptionValue("");
    setSnoozeHours(4);
  };

  const startModal = (kind: DecisionKind) => {
    setOpen(false);
    setModal({ kind });
    // Pre-fill the exception value with the most plausible candidate
    // for the picked scope, so the operator just clicks Confirm if
    // they want the obvious default.
    if (kind === "false_positive") {
      setExceptionKind("none");
      setExceptionValue("");
    }
  };

  const submit = async () => {
    if (!modal) return;
    setSubmitting(true);
    try {
      let url = "";
      const body: Record<string, unknown> = {
        actor: props.actor ?? "dashboard:anonymous",
      };
      if (reason.trim()) body.reason = reason.trim();

      switch (modal.kind) {
        case "resolve":
          url = `/api/tc/incidents/${props.incidentId}/resolve`;
          break;
        case "false_positive":
          url = `/api/tc/incidents/${props.incidentId}/false-positive`;
          if (exceptionKind !== "none" && exceptionValue.trim()) {
            body.exception_scope = {
              kind: exceptionKind,
              value: exceptionValue.trim(),
            };
            if (props.ruleId) body.exception_rule_id = props.ruleId;
          }
          break;
        case "accept_risk":
          url = `/api/tc/incidents/${props.incidentId}/accept-risk`;
          if (!reason.trim()) {
            alert("Accept Risk needs a reason.");
            setSubmitting(false);
            return;
          }
          break;
        case "snooze":
          url = `/api/tc/incidents/${props.incidentId}/snooze`;
          body.snooze_hours = snoozeHours;
          break;
        case "delete":
          url = `/api/tc/admin/incidents/${props.incidentId}`;
          if (
            !window.confirm(
              "Hard-delete this incident? This cannot be undone.",
            )
          ) {
            setSubmitting(false);
            return;
          }
          break;
      }

      const res = await fetch(url, {
        method: modal.kind === "delete" ? "DELETE" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.text();
        alert(`${modal.kind} failed: ${err}`);
      } else {
        props.onDone?.(modal.kind);
        close();
      }
    } finally {
      setSubmitting(false);
    }
  };

  const valueOptions = (): { label: string; value: string }[] => {
    const opts: { label: string; value: string }[] = [];
    if (exceptionKind === "asset" && props.assetHostname) {
      opts.push({ label: props.assetHostname, value: props.assetHostname });
    }
    if (exceptionKind === "username" && props.username) {
      opts.push({ label: props.username, value: props.username });
    }
    if (exceptionKind === "source_ip" && props.sourceIp) {
      opts.push({ label: props.sourceIp, value: props.sourceIp });
    }
    return opts;
  };

  const variant = props.variant ?? "dropdown";

  const items = (
    <>
      <MenuItem
        icon={<Check size={11} />}
        label="Resolve"
        hint="I handled this"
        onClick={() => startModal("resolve")}
      />
      <MenuItem
        icon={<Cross size={11} />}
        label="False Positive"
        hint="Detection was wrong"
        onClick={() => startModal("false_positive")}
      />
      <MenuItem
        icon={<Shield size={11} />}
        label="Accept Risk"
        hint="Business accepts the risk"
        onClick={() => startModal("accept_risk")}
      />
      <MenuItem
        icon={<Clock size={11} />}
        label="Snooze"
        hint="Remind me in N hours"
        onClick={() => startModal("snooze")}
      />
      {props.adminMode && (
        <MenuItem
          icon={<Trash2 size={11} />}
          label="Delete (admin)"
          hint="Hard-delete this row"
          onClick={() => startModal("delete")}
          danger
        />
      )}
    </>
  );

  return (
    <>
      {variant === "inline" ? (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            background: "var(--tc-surface)",
            border: "1px solid var(--tc-border)",
            fontSize: 12,
          }}
        >
          {items}
        </div>
      ) : (
        <div style={{ position: "relative" }}>
          <button
            className="inc-btn-sm"
            onClick={() => setOpen((v) => !v)}
            title="Operator decision"
          >
            Decision <ChevronDown size={9} />
          </button>
          {open && (
            <div
              onMouseLeave={() => setOpen(false)}
              style={{
                position: "absolute",
                right: 0,
                top: "100%",
                marginTop: 4,
                background: "var(--tc-surface)",
                border: "1px solid var(--tc-border)",
                minWidth: 200,
                zIndex: 50,
                fontSize: 12,
              }}
            >
              {items}
            </div>
          )}
        </div>
      )}

      {modal && (
        <ModalShell title={titleFor(modal.kind)} onClose={close}>
          {modal.kind === "resolve" && (
            <>
              <p style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 12 }}>
                Close this incident as resolved. The dashboard stops
                showing it in the active queue but keeps it in the
                history.
              </p>
              <Field label="Optional note">
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  rows={3}
                  style={textareaStyle}
                  placeholder="e.g. Blocked source IP at the firewall."
                />
              </Field>
            </>
          )}

          {modal.kind === "false_positive" && (
            <>
              <p style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 12 }}>
                Mark as false positive. Optionally also create a
                detection-engine exception so the rule stops firing on
                this scope.
              </p>
              <Field label="Reason">
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={inputStyle}
                  placeholder="e.g. Internal admin tooling."
                />
              </Field>
              <Field label="Also create exception">
                <select
                  value={exceptionKind}
                  onChange={(e) =>
                    setExceptionKind(e.target.value as ExceptionKind | "none")
                  }
                  style={inputStyle}
                >
                  <option value="none">No — one-off only</option>
                  <option value="asset">Yes — for this asset</option>
                  <option value="username">Yes — for this user</option>
                  <option value="source_ip">Yes — for this source IP</option>
                </select>
              </Field>
              {exceptionKind !== "none" && (
                <Field label="Exception value">
                  <input
                    value={exceptionValue}
                    onChange={(e) => setExceptionValue(e.target.value)}
                    list={`opts-${modal.kind}`}
                    style={inputStyle}
                    placeholder={
                      exceptionKind === "asset"
                        ? "hostname"
                        : exceptionKind === "username"
                          ? "username"
                          : "x.x.x.x"
                    }
                  />
                  <datalist id={`opts-${modal.kind}`}>
                    {valueOptions().map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </datalist>
                </Field>
              )}
            </>
          )}

          {modal.kind === "accept_risk" && (
            <>
              <p style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 12 }}>
                Mark this incident as a risk the organisation accepts.
                Stays in the compliance log under the assigned owner.
              </p>
              <Field label="Reason (required)">
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  rows={3}
                  style={textareaStyle}
                  placeholder="e.g. Legacy system, replacement scheduled Q4."
                />
              </Field>
            </>
          )}

          {modal.kind === "snooze" && (
            <>
              <p style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 12 }}>
                Hide this incident from the active queue. It comes back
                automatically when the snooze expires.
              </p>
              <Field label="Snooze for">
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {[1, 4, 24, 72].map((h) => (
                    <button
                      key={h}
                      onClick={() => setSnoozeHours(h)}
                      style={{
                        padding: "6px 12px",
                        background:
                          snoozeHours === h
                            ? "var(--tc-red)"
                            : "var(--tc-surface-alt)",
                        color: snoozeHours === h ? "white" : "var(--tc-text)",
                        border: "1px solid var(--tc-border)",
                        cursor: "pointer",
                        fontSize: 11,
                        fontFamily: "ui-monospace, monospace",
                      }}
                    >
                      {h < 24 ? `${h} h` : `${h / 24} d`}
                    </button>
                  ))}
                  <input
                    type="number"
                    min={1}
                    max={720}
                    value={snoozeHours}
                    onChange={(e) =>
                      setSnoozeHours(Math.max(1, Number(e.target.value) || 1))
                    }
                    style={{ ...inputStyle, width: 90 }}
                  />
                </div>
              </Field>
              <Field label="Reason (optional)">
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={inputStyle}
                  placeholder="e.g. Waiting for vendor patch."
                />
              </Field>
            </>
          )}

          <div
            style={{ display: "flex", gap: 8, marginTop: 16, justifyContent: "flex-end" }}
          >
            <button onClick={close} disabled={submitting} style={btnSecondary}>
              Cancel
            </button>
            <button
              onClick={submit}
              disabled={submitting}
              style={modal.kind === "delete" ? btnDanger : btnPrimary}
            >
              {submitting ? "..." : confirmLabel(modal.kind)}
            </button>
          </div>
        </ModalShell>
      )}
    </>
  );
}

// ── Sub-components ──────────────────────────────────────────────────

function MenuItem(props: {
  icon: React.ReactNode;
  label: string;
  hint: string;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      onClick={props.onClick}
      style={{
        width: "100%",
        textAlign: "left",
        padding: "8px 12px",
        background: "transparent",
        border: "none",
        borderBottom: "1px solid var(--tc-border)",
        cursor: "pointer",
        color: props.danger ? "var(--tc-red)" : "var(--tc-text)",
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontSize: 12,
      }}
      onMouseEnter={(e) =>
        (e.currentTarget.style.background = "var(--tc-surface-alt)")
      }
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      {props.icon}
      <span style={{ flex: 1 }}>
        <div style={{ fontWeight: 600 }}>{props.label}</div>
        <div
          style={{
            fontSize: 10,
            color: "var(--tc-text-muted)",
            fontWeight: 400,
          }}
        >
          {props.hint}
        </div>
      </span>
    </button>
  );
}

function ModalShell(props: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}) {
  return (
    <div
      onClick={props.onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: 20,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "var(--tc-surface)",
          border: "1px solid var(--tc-border)",
          padding: 24,
          maxWidth: 480,
          width: "100%",
          fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
        }}
      >
        <h3
          style={{
            fontSize: 14,
            fontWeight: 700,
            margin: 0,
            marginBottom: 14,
            color: "var(--tc-text)",
            fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
          }}
        >
          {props.title}
        </h3>
        {props.children}
      </div>
    </div>
  );
}

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div
        style={{
          fontSize: 10,
          fontWeight: 600,
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: 4,
          fontFamily: "ui-monospace, monospace",
        }}
      >
        {props.label}
      </div>
      {props.children}
    </div>
  );
}

// ── Styles ──────────────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "6px 8px",
  background: "var(--tc-surface-alt)",
  border: "1px solid var(--tc-border)",
  color: "var(--tc-text)",
  fontSize: 12,
  fontFamily: "ui-monospace, monospace",
};

const textareaStyle: React.CSSProperties = {
  ...inputStyle,
  resize: "vertical",
  fontFamily: "inherit",
};

const btnPrimary: React.CSSProperties = {
  padding: "6px 14px",
  background: "var(--tc-red)",
  color: "white",
  border: "none",
  cursor: "pointer",
  fontSize: 12,
  fontWeight: 600,
  fontFamily: "ui-monospace, monospace",
};

const btnSecondary: React.CSSProperties = {
  padding: "6px 14px",
  background: "transparent",
  color: "var(--tc-text-muted)",
  border: "1px solid var(--tc-border)",
  cursor: "pointer",
  fontSize: 12,
  fontFamily: "ui-monospace, monospace",
};

const btnDanger: React.CSSProperties = {
  ...btnPrimary,
  background: "var(--tc-red)",
};

function titleFor(kind: DecisionKind): string {
  switch (kind) {
    case "resolve":
      return "Resolve incident";
    case "false_positive":
      return "Mark as false positive";
    case "accept_risk":
      return "Accept risk";
    case "snooze":
      return "Snooze incident";
    case "delete":
      return "Delete incident";
  }
}

function confirmLabel(kind: DecisionKind): string {
  switch (kind) {
    case "resolve":
      return "Resolve";
    case "false_positive":
      return "Mark FP";
    case "accept_risk":
      return "Accept";
    case "snooze":
      return "Snooze";
    case "delete":
      return "DELETE";
  }
}

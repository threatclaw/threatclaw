/**
 * InvestigationTimeline — Phase 9o
 *
 * Affiche la trace d'investigation de l'agent sur un incident. Chaque
 * step est une action vérifiable persistée dans
 * `incident_investigation_steps` (V72) :
 *   - skill_call : appel à un skill connecté (firewall, IP rep…)
 *   - llm_call   : appel L1 ReAct ou L2 forensic
 *   - graph_step : franchissement d'un node CACAO
 *   - derive_actions : dérivation déterministe du panel HITL
 *   - incident_created / remediation_executed / note
 *
 * Rendu **collapsed par défaut** (le RSSI ouvre quand il veut auditer)
 * pour ne pas dominer l'écran face à la chronologie d'attaque qui
 * reste prioritaire en haut.
 *
 * Polluant connu volontairement écarté : les cycles L1 ReAct globaux
 * toutes les 15 min n'apparaissent **pas** ici — seuls les steps
 * attachés à un incident_id donné sont persistés.
 */

import React, { useState } from "react";

// ─── Types miroirs des structs Rust (db::threatclaw_store) ──────────

export type StepKind =
  | "skill_call"
  | "llm_call"
  | "graph_step"
  | "derive_actions"
  | "incident_created"
  | "remediation_executed"
  | "note"
  | "other";

export type StepStatus =
  | "ok"
  | "error"
  | "timeout"
  | "no_match"
  | "fallback"
  | "other";

export interface InvestigationStep {
  id: number;
  incident_id: number;
  kind: StepKind;
  skill_id: string | null;
  summary: string;
  payload: Record<string, unknown>;
  duration_ms: number | null;
  status: StepStatus;
  created_at: string;
}

interface Props {
  steps: InvestigationStep[] | null | undefined;
}

// ─── Helpers visuels ────────────────────────────────────────────────

function kindLabel(kind: StepKind): string {
  switch (kind) {
    case "skill_call":
      return "SKILL";
    case "llm_call":
      return "LLM";
    case "graph_step":
      return "GRAPH";
    case "derive_actions":
      return "ACTIONS";
    case "incident_created":
      return "OUVERT";
    case "remediation_executed":
      return "REMEDIATION";
    case "note":
      return "NOTE";
    default:
      return "STEP";
  }
}

function kindColor(kind: StepKind): string {
  switch (kind) {
    case "llm_call":
      return "#7e8bff"; // blue
    case "skill_call":
      return "#30a050"; // green
    case "graph_step":
      return "#a060ff"; // purple
    case "derive_actions":
      return "#ff6030"; // orange (matches HITL)
    case "incident_created":
      return "#d03020"; // red
    case "remediation_executed":
      return "#ff9020"; // amber
    case "note":
      return "#909090"; // grey
    default:
      return "#666";
  }
}

function statusBadge(status: StepStatus): React.ReactElement | null {
  if (status === "ok") return null; // implicit
  const palette: Record<string, { bg: string; fg: string }> = {
    error: { bg: "rgba(208,48,32,0.18)", fg: "#d03020" },
    timeout: { bg: "rgba(208,48,32,0.18)", fg: "#d03020" },
    fallback: { bg: "rgba(255,144,32,0.18)", fg: "#ff9020" },
    no_match: { bg: "rgba(144,144,144,0.18)", fg: "#a0a0a0" },
    other: { bg: "rgba(144,144,144,0.18)", fg: "#a0a0a0" },
  };
  const c = palette[status] ?? palette.other;
  return (
    <span
      style={{
        fontSize: 9,
        padding: "1px 5px",
        background: c.bg,
        color: c.fg,
        border: `1px solid ${c.fg}55`,
        textTransform: "uppercase",
        fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
      }}
    >
      {status.replace("_", " ")}
    </span>
  );
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString("fr-FR", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

function fmtDuration(ms: number | null): string {
  if (ms == null) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}min`;
}

// ─── Composant ──────────────────────────────────────────────────────

export function InvestigationTimeline({ steps }: Props): React.ReactElement | null {
  const [expanded, setExpanded] = useState<boolean>(false);
  const [openStepIds, setOpenStepIds] = useState<Set<number>>(new Set());

  const list = steps ?? [];
  if (list.length === 0) return null;

  const toggle = (id: number) => {
    setOpenStepIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Counters for the collapsed header — gives the operator a sense of
  // "what happened" without expanding.
  const countByKind = list.reduce<Partial<Record<StepKind, number>>>(
    (acc, s) => {
      acc[s.kind] = (acc[s.kind] ?? 0) + 1;
      return acc;
    },
    {},
  );

  return (
    <section style={{
      border: "1px solid var(--tc-border)",
      background: "var(--tc-surface)",
      marginTop: 8,
    }}>
      <button
        onClick={() => setExpanded((x) => !x)}
        style={{
          width: "100%",
          padding: "10px 12px",
          background: "transparent",
          border: "none",
          color: "var(--tc-text)",
          textAlign: "left",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 12,
          fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
          fontSize: 12,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        <span style={{ fontSize: 10 }}>{expanded ? "▼" : "▶"}</span>
        <span>Chronologie d&apos;analyse</span>
        <span style={{ fontWeight: 400, fontSize: 10, color: "var(--tc-text-muted)", letterSpacing: 0 }}>
          {list.length} étape{list.length > 1 ? "s" : ""}
          {Object.entries(countByKind).map(([kind, count]) => (
            <span key={kind} style={{ marginLeft: 8 }}>
              · {count} {kindLabel(kind as StepKind).toLowerCase()}
            </span>
          ))}
        </span>
      </button>

      {expanded && (
        <div style={{ padding: "0 12px 12px" }}>
          <ol style={{
            listStyle: "none",
            margin: 0,
            padding: 0,
            display: "flex",
            flexDirection: "column",
            gap: 4,
            borderLeft: "1px solid var(--tc-border)",
            paddingLeft: 12,
          }}>
            {list.map((step) => {
              const open = openStepIds.has(step.id);
              const color = kindColor(step.kind);
              return (
                <li key={step.id}>
                  <button
                    onClick={() => toggle(step.id)}
                    style={{
                      width: "100%",
                      padding: "6px 8px",
                      background: "var(--tc-surface-alt)",
                      border: "1px solid var(--tc-border)",
                      color: "var(--tc-text)",
                      textAlign: "left",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      fontSize: 11,
                    }}
                    title={`Cliquer pour ${open ? "replier" : "déplier"}`}
                  >
                    <span style={{
                      fontSize: 9,
                      color: "var(--tc-text-muted)",
                      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                      minWidth: 60,
                    }}>
                      {fmtTime(step.created_at)}
                    </span>
                    <span style={{
                      fontSize: 9,
                      fontWeight: 700,
                      padding: "1px 5px",
                      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                      background: `${color}22`,
                      color,
                      border: `1px solid ${color}55`,
                      minWidth: 60,
                      textAlign: "center",
                    }}>
                      {kindLabel(step.kind)}
                    </span>
                    {step.skill_id && (
                      <span style={{
                        fontSize: 9,
                        color: "var(--tc-text-muted)",
                        fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                      }}>
                        {step.skill_id}
                      </span>
                    )}
                    <span style={{ flex: 1, color: "var(--tc-text-sec)" }}>
                      {step.summary}
                    </span>
                    {statusBadge(step.status)}
                    {step.duration_ms != null && (
                      <span style={{
                        fontSize: 9,
                        color: "var(--tc-text-muted)",
                        fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                      }}>
                        {fmtDuration(step.duration_ms)}
                      </span>
                    )}
                    <span style={{ fontSize: 9, color: "var(--tc-text-muted)" }}>
                      {open ? "▼" : "▶"}
                    </span>
                  </button>
                  {open && (
                    <pre style={{
                      margin: "2px 0 0 0",
                      padding: "8px 10px",
                      background: "var(--tc-surface)",
                      border: "1px solid var(--tc-border)",
                      borderTop: "none",
                      fontSize: 10,
                      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                      color: "var(--tc-text-muted)",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      maxHeight: 300,
                      overflowY: "auto",
                    }}>
                      {JSON.stringify(step.payload, null, 2)}
                    </pre>
                  )}
                </li>
              );
            })}
          </ol>
        </div>
      )}
    </section>
  );
}

export default InvestigationTimeline;

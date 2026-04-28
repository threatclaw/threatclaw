"use client";

import React, { useEffect, useState } from "react";
import { useLocale } from "@/lib/useLocale";

// Sprint 4 — investigation graph catalog + LLM-assisted draft.
//
// Single-page UI: top section lists graphs already shipped (read from
// the same TC_GRAPHS_DIR the dispatcher loads at boot). Bottom section
// is a "draft from sigma" panel that calls /api/tc/graphs/draft-from-sigma,
// renders the YAML in an editable textarea, validates locally on the
// server side, and saves to disk via /api/tc/graphs/save.

interface GraphItem {
  name: string;
  sigma_rule: string;
  description?: string;
  file?: string;
}

interface DraftResponse {
  yaml?: string;
  valid?: boolean;
  errors?: string[];
  graph_name?: string | null;
  model?: string;
  error?: string;
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

export default function GraphsPage() {
  const { locale } = useLocale();
  const fr = locale === "fr";

  const [graphs, setGraphs] = useState<GraphItem[]>([]);
  const [dir, setDir] = useState<string>("");
  const [loading, setLoading] = useState(true);

  const [ruleId, setRuleId] = useState("");
  const [sampleAlertsText, setSampleAlertsText] = useState("");
  const [drafting, setDrafting] = useState(false);
  const [draft, setDraft] = useState<DraftResponse | null>(null);
  const [yamlEdit, setYamlEdit] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      const res = await fetch("/api/tc/graphs");
      const j = await res.json();
      setGraphs(j.graphs || []);
      setDir(j.dir || "");
    } catch (e) {
      // best-effort, keep current list
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onDraft() {
    setDraft(null);
    setSaveMsg(null);
    if (!ruleId.trim()) return;
    setDrafting(true);
    let sample: any = [];
    if (sampleAlertsText.trim()) {
      try {
        sample = JSON.parse(sampleAlertsText);
      } catch {
        setDraft({ error: fr ? "JSON d'exemples invalide" : "invalid sample JSON" });
        setDrafting(false);
        return;
      }
    }
    try {
      const res = await fetch("/api/tc/graphs/draft-from-sigma", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_id: ruleId.trim(), sample_alerts: sample }),
      });
      const j: DraftResponse = await res.json();
      setDraft(j);
      setYamlEdit(j.yaml || "");
    } catch (e: any) {
      setDraft({ error: String(e?.message || e) });
    } finally {
      setDrafting(false);
    }
  }

  async function onSave() {
    setSaveMsg(null);
    setSaving(true);
    try {
      const res = await fetch("/api/tc/graphs/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yaml: yamlEdit }),
      });
      const j = await res.json();
      if (j.error) {
        setSaveMsg({ kind: "err", text: j.error });
      } else {
        setSaveMsg({
          kind: "ok",
          text: fr
            ? `Sauvegardé : ${j.file}. Redémarrer le core pour activer le graph.`
            : `Saved: ${j.file}. Restart the core to activate the graph.`,
        });
        refresh();
      }
    } catch (e: any) {
      setSaveMsg({ kind: "err", text: String(e?.message || e) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ padding: "20px 28px", color: "var(--tc-text)", maxWidth: "1100px" }}>
      <h1 style={{ fontSize: "16px", fontWeight: 800, marginBottom: "4px" }}>
        {fr ? "Graphs d'investigation" : "Investigation graphs"}
      </h1>
      <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "20px" }}>
        {fr
          ? "Catalogue des playbooks déterministes (CACAO v2) chargés au boot. Le dispatcher les utilise pour court-circuiter le ReAct LLM sur les patterns connus."
          : "Catalog of deterministic playbooks (CACAO v2) loaded at boot. The dispatcher short-circuits the ReAct LLM on known patterns."}
      </div>

      {/* ── List ── */}
      <section style={{ marginBottom: "32px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "10px", marginBottom: "10px" }}>
          <h2 style={{ fontSize: "12px", fontWeight: 700, textTransform: "uppercase", color: "var(--tc-text-sec)" }}>
            {fr ? "Graphs livrés" : "Shipped graphs"} ({graphs.length})
          </h2>
          <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontFamily: "monospace" }}>{dir}</span>
        </div>
        {loading ? (
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{fr ? "Chargement…" : "Loading…"}</div>
        ) : graphs.length === 0 ? (
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", fontStyle: "italic" }}>
            {fr ? "Aucun graph trouvé dans le dossier." : "No graph found in directory."}
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "8px" }}>
            {graphs.map((g) => (
              <div
                key={g.name}
                style={{
                  background: "var(--tc-bg)",
                  border: "1px solid var(--tc-border)",
                  borderRadius: "var(--tc-radius-sm)",
                  padding: "10px 12px",
                }}
              >
                <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "2px" }}>
                  {g.name}
                </div>
                <div style={{ fontSize: "9px", fontFamily: "monospace", color: "var(--tc-blue)", marginBottom: "4px" }}>
                  trigger: {g.sigma_rule}
                </div>
                {g.description && (
                  <div
                    style={{
                      fontSize: "10px",
                      color: "var(--tc-text-muted)",
                      lineHeight: 1.4,
                      maxHeight: "48px",
                      overflow: "hidden",
                    }}
                  >
                    {g.description.split("\n")[0]}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── Draft ── */}
      <section>
        <h2
          style={{
            fontSize: "12px",
            fontWeight: 700,
            textTransform: "uppercase",
            color: "var(--tc-text-sec)",
            marginBottom: "10px",
          }}
        >
          {fr ? "Générer un graph depuis une sigma rule" : "Draft a graph from a sigma rule"}
        </h2>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "12px" }}>
          {fr
            ? "Demande à l'IA locale (Instruct) un brouillon CACAO v2. La sortie est validée (parse + compile) avant d'être proposée à la sauvegarde. Un graph mal formé est rejeté côté backend."
            : "Asks the local Instruct LLM for a CACAO v2 draft. The output is validated (parse + compile) before saving. Malformed graphs are rejected server-side."}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "10px", marginBottom: "12px" }}>
          <div>
            <label style={labelStyle}>{fr ? "rule_id sigma" : "sigma rule_id"}</label>
            <input
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              placeholder="wazuh-100110"
              style={{
                width: "100%",
                padding: "6px 8px",
                fontSize: "11px",
                fontFamily: "monospace",
                background: "var(--tc-input)",
                border: "1px solid var(--tc-border)",
                borderRadius: "var(--tc-radius-sm)",
                color: "var(--tc-text)",
              }}
            />
          </div>
          <div>
            <label style={labelStyle}>
              {fr ? "Alertes d'exemple (JSON, optionnel)" : "Sample alerts (JSON, optional)"}
            </label>
            <textarea
              value={sampleAlertsText}
              onChange={(e) => setSampleAlertsText(e.target.value)}
              placeholder='[{"hostname":"srv-01","src_ip":"10.0.0.5","level":"high"}]'
              rows={3}
              style={{
                width: "100%",
                padding: "6px 8px",
                fontSize: "10px",
                fontFamily: "monospace",
                background: "var(--tc-input)",
                border: "1px solid var(--tc-border)",
                borderRadius: "var(--tc-radius-sm)",
                color: "var(--tc-text)",
                resize: "vertical",
              }}
            />
          </div>
        </div>

        <button
          disabled={!ruleId.trim() || drafting}
          onClick={onDraft}
          style={{
            padding: "8px 14px",
            fontSize: "11px",
            fontWeight: 700,
            fontFamily: "inherit",
            background: drafting ? "var(--tc-input)" : "var(--tc-red)",
            color: drafting ? "var(--tc-text-muted)" : "#fff",
            border: "1px solid var(--tc-border)",
            borderRadius: "var(--tc-radius-sm)",
            cursor: drafting || !ruleId.trim() ? "not-allowed" : "pointer",
            marginBottom: "16px",
          }}
        >
          {drafting ? (fr ? "Génération en cours…" : "Drafting…") : fr ? "Générer" : "Draft"}
        </button>

        {draft && (
          <div style={{ marginTop: "10px" }}>
            {draft.error && (
              <div
                style={{
                  fontSize: "11px",
                  color: "#e04040",
                  background: "rgba(224,64,64,0.08)",
                  border: "1px solid rgba(224,64,64,0.3)",
                  padding: "8px 10px",
                  borderRadius: "var(--tc-radius-sm)",
                  marginBottom: "10px",
                }}
              >
                {draft.error}
              </div>
            )}

            {draft.yaml !== undefined && (
              <>
                <div style={{ display: "flex", alignItems: "baseline", gap: "10px", marginBottom: "6px" }}>
                  <label style={labelStyle}>YAML</label>
                  <span
                    style={{
                      fontSize: "9px",
                      fontWeight: 700,
                      padding: "1px 6px",
                      borderRadius: "3px",
                      background: draft.valid ? "rgba(48,160,80,0.12)" : "rgba(224,64,64,0.12)",
                      color: draft.valid ? "#30a050" : "#e04040",
                    }}
                  >
                    {draft.valid ? (fr ? "VALIDE" : "VALID") : fr ? "INVALIDE" : "INVALID"}
                  </span>
                  {draft.graph_name && (
                    <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontFamily: "monospace" }}>
                      name: {draft.graph_name}
                    </span>
                  )}
                  {draft.model && (
                    <span style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>
                      model: {draft.model}
                    </span>
                  )}
                </div>

                {draft.errors && draft.errors.length > 0 && (
                  <ul style={{ margin: "0 0 8px 0", paddingLeft: "16px", fontSize: "10px", color: "#e04040" }}>
                    {draft.errors.map((e, i) => (
                      <li key={i}>{e}</li>
                    ))}
                  </ul>
                )}

                <textarea
                  value={yamlEdit}
                  onChange={(e) => setYamlEdit(e.target.value)}
                  rows={20}
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    fontSize: "11px",
                    fontFamily: "monospace",
                    background: "var(--tc-input)",
                    border: "1px solid var(--tc-border)",
                    borderRadius: "var(--tc-radius-sm)",
                    color: "var(--tc-text)",
                    resize: "vertical",
                    marginBottom: "10px",
                  }}
                />

                <button
                  onClick={onSave}
                  disabled={saving || !yamlEdit.trim()}
                  style={{
                    padding: "8px 14px",
                    fontSize: "11px",
                    fontWeight: 700,
                    fontFamily: "inherit",
                    background: "var(--tc-input)",
                    color: "var(--tc-text)",
                    border: "1px solid var(--tc-border)",
                    borderRadius: "var(--tc-radius-sm)",
                    cursor: saving ? "not-allowed" : "pointer",
                  }}
                >
                  {saving ? (fr ? "Sauvegarde…" : "Saving…") : fr ? "Sauvegarder" : "Save"}
                </button>

                {saveMsg && (
                  <div
                    style={{
                      marginTop: "10px",
                      fontSize: "11px",
                      padding: "6px 10px",
                      borderRadius: "var(--tc-radius-sm)",
                      background:
                        saveMsg.kind === "ok" ? "rgba(48,160,80,0.08)" : "rgba(224,64,64,0.08)",
                      color: saveMsg.kind === "ok" ? "#30a050" : "#e04040",
                      border: `1px solid ${saveMsg.kind === "ok" ? "rgba(48,160,80,0.3)" : "rgba(224,64,64,0.3)"}`,
                    }}
                  >
                    {saveMsg.text}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

"use client";

import React, { useState, useCallback, useMemo } from "react";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { PageShell } from "@/components/chrome/PageShell";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import {
  Search, RefreshCw, X, Clock, Server, Tag as TagIcon,
  ChevronDown, ChevronRight, Database, Filter, Bookmark, Trash2,
} from "lucide-react";

type LogRecord = {
  id: number;
  tag: string | null;
  time: string;
  hostname: string | null;
  data: Record<string, unknown>;
};

type SearchResponse = {
  logs: LogRecord[];
  next_cursor: string | null;
  scanned_chunks: number;
  error?: string;
};

type SavedQueryParams = {
  hostname?: string;
  tag?: string;
  q?: string;
  rangeKey?: string;
  customFrom?: string;
  customTo?: string;
};

type SavedQuery = {
  id: number;
  name: string;
  params: SavedQueryParams;
  created_at: string;
};

const TAG_PRESETS = ["syslog", "wazuh", "osquery", "zeek", "suricata", "fluent"];

const RANGE_PRESETS: Array<{ key: string; labelFr: string; labelEn: string; minutes: number | null }> = [
  { key: "15m",  labelFr: "15 min", labelEn: "15 min", minutes: 15 },
  { key: "1h",   labelFr: "1 h",    labelEn: "1 h",    minutes: 60 },
  { key: "24h",  labelFr: "24 h",   labelEn: "24 h",   minutes: 24 * 60 },
  { key: "7d",   labelFr: "7 j",    labelEn: "7 d",    minutes: 7 * 24 * 60 },
  { key: "30d",  labelFr: "30 j",   labelEn: "30 d",   minutes: 30 * 24 * 60 },
];

function previewMessage(data: Record<string, unknown>): string {
  for (const key of ["message", "msg", "analysis", "full_log", "log"]) {
    const v = data?.[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  try { return JSON.stringify(data); } catch { return ""; }
}

export default function HuntPage() {
  const locale = useLocale();
  const labels = useMemo(() => ({
    title:        locale === "fr" ? "Recherche logs"  : "Log search",
    subtitle:     locale === "fr"
      ? "Puits de log : filtre, fouille, pivote."
      : "Log lake : filter, hunt, pivot.",
    hostname:     locale === "fr" ? "Hostname"        : "Hostname",
    tag:          locale === "fr" ? "Tag"             : "Tag",
    range:        locale === "fr" ? "Plage"           : "Range",
    custom:       locale === "fr" ? "Personnalisée"   : "Custom",
    from:         locale === "fr" ? "De"              : "From",
    to:           locale === "fr" ? "À"               : "To",
    freeText:     locale === "fr" ? "Recherche libre" : "Free-text search",
    search:       locale === "fr" ? "Rechercher"      : "Search",
    reset:        locale === "fr" ? "Réinitialiser"   : "Reset",
    refresh:      locale === "fr" ? "Actualiser"      : "Refresh",
    noResults:    locale === "fr" ? "Aucun log dans cette fenêtre." : "No log in this window.",
    runQuery:     locale === "fr" ? "Lance une recherche pour fouiller le puits." : "Run a query to dig into the lake.",
    loading:      locale === "fr" ? "Chargement..."   : "Loading...",
    loadMore:     locale === "fr" ? "Charger plus"    : "Load more",
    chunks:       locale === "fr" ? "chunks scannés"  : "chunks scanned",
    results:      locale === "fr" ? "résultats"       : "results",
    raw:          locale === "fr" ? "JSON brut"       : "Raw JSON",
    time:         locale === "fr" ? "Heure"           : "Time",
    host:         locale === "fr" ? "Hôte"            : "Host",
    msg:          locale === "fr" ? "Message"         : "Message",
    pivotIncident:locale === "fr" ? "Pivoter depuis incident" : "Pivot from incident",
    error:        locale === "fr" ? "Erreur"          : "Error",
    saved:        locale === "fr" ? "Recherches enregistrées" : "Saved searches",
    savePrompt:   locale === "fr" ? "Nom de la recherche ?" : "Name this search:",
    save:         locale === "fr" ? "Enregistrer"     : "Save",
    noSaved:      locale === "fr" ? "Aucune recherche enregistrée." : "No saved searches yet.",
    delete:       locale === "fr" ? "Supprimer"       : "Delete",
  }), [locale]);

  const [hostname, setHostname] = useState("");
  const [tag, setTag] = useState("");
  const [q, setQ] = useState("");
  const [rangeKey, setRangeKey] = useState<string>("24h");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogRecord[]>([]);
  const [scannedChunks, setScannedChunks] = useState<number | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [saved, setSaved] = useState<SavedQuery[]>([]);
  // Set to true when filters were hydrated programmatically (URL pivot,
  // saved query). A second effect consumes the flag once React has
  // committed the new filter state — that guarantees runSearch reads
  // the freshly-committed hostname/tag/range instead of an empty
  // closure (the previous setTimeout-0 trick raced the commit and
  // produced empty queries on the incident → /hunt pivot).
  const [autoSearchPending, setAutoSearchPending] = useState(false);
  const [savingBusy, setSavingBusy] = useState(false);
  const [assetHostnames, setAssetHostnames] = useState<string[]>([]);

  const resolveRange = useCallback((): { from?: string; to?: string } => {
    if (rangeKey === "custom") {
      const out: { from?: string; to?: string } = {};
      if (customFrom) out.from = new Date(customFrom).toISOString();
      if (customTo) out.to = new Date(customTo).toISOString();
      return out;
    }
    const preset = RANGE_PRESETS.find(p => p.key === rangeKey);
    if (!preset || preset.minutes === null) return {};
    const now = new Date();
    const from = new Date(now.getTime() - preset.minutes * 60_000);
    return { from: from.toISOString(), to: now.toISOString() };
  }, [rangeKey, customFrom, customTo]);

  const buildQS = useCallback((cursor: string | null): string => {
    const qs = new URLSearchParams();
    if (hostname.trim()) qs.set("hostname", hostname.trim());
    if (tag.trim()) qs.set("tag", tag.trim());
    if (q.trim()) qs.set("q", q.trim());
    const range = resolveRange();
    if (range.from) qs.set("from", range.from);
    if (range.to)   qs.set("to",   range.to);
    qs.set("limit", "100");
    if (cursor) qs.set("cursor", cursor);
    return qs.toString();
  }, [hostname, tag, q, resolveRange]);

  const runSearch = useCallback(async (append: boolean) => {
    setLoading(true);
    setError(null);
    try {
      const cursor = append ? nextCursor : null;
      const res = await fetch(`/api/tc/logs/search?${buildQS(cursor)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: SearchResponse = await res.json();
      if (json.error) throw new Error(json.error);
      setScannedChunks(json.scanned_chunks);
      setNextCursor(json.next_cursor);
      setLogs(prev => append ? [...prev, ...json.logs] : json.logs);
      setHasSearched(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [buildQS, nextCursor]);

  const reset = () => {
    setHostname(""); setTag(""); setQ("");
    setRangeKey("24h"); setCustomFrom(""); setCustomTo("");
    setLogs([]); setScannedChunks(null); setNextCursor(null);
    setExpanded(null); setHasSearched(false); setError(null);
  };

  const loadSaved = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/hunt/saved");
      if (!res.ok) return;
      const json = await res.json();
      if (Array.isArray(json.items)) setSaved(json.items);
    } catch { /* sidebar is best-effort */ }
  }, []);

  React.useEffect(() => { loadSaved(); }, [loadSaved]);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/tc/assets?limit=1000");
        if (!res.ok) return;
        const json = await res.json();
        const raw = (json?.assets ?? []) as Array<{ hostname?: string | null; name?: string }>;
        const list: string[] = Array.from(new Set(
          raw
            .map(a => a.hostname || a.name || "")
            .filter((s): s is string => typeof s === "string" && s.length > 0)
        )).sort((a, b) => a.localeCompare(b));
        if (!cancelled) setAssetHostnames(list);
      } catch { /* autocomplete is best-effort */ }
    })();
    return () => { cancelled = true; };
  }, []);

  const saveCurrent = async () => {
    const name = window.prompt(labels.savePrompt);
    if (!name || !name.trim()) return;
    setSavingBusy(true);
    try {
      const params: SavedQueryParams = {
        hostname: hostname || undefined,
        tag: tag || undefined,
        q: q || undefined,
        rangeKey,
        customFrom: rangeKey === "custom" ? customFrom : undefined,
        customTo:   rangeKey === "custom" ? customTo   : undefined,
      };
      const res = await fetch("/api/tc/hunt/saved", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), params }),
      });
      if (res.ok) await loadSaved();
    } finally {
      setSavingBusy(false);
    }
  };

  const applySaved = (sq: SavedQuery) => {
    const p = sq.params || {};
    setHostname(p.hostname || "");
    setTag(p.tag || "");
    setQ(p.q || "");
    setRangeKey(p.rangeKey || "24h");
    setCustomFrom(p.customFrom || "");
    setCustomTo(p.customTo || "");
    setAutoSearchPending(true);
  };

  const deleteSaved = async (id: number) => {
    await fetch(`/api/tc/hunt/saved/${id}`, { method: "DELETE" });
    await loadSaved();
  };

  // Hydrate filters from query params (incident pivot lands here).
  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const url = new URL(window.location.href);
    let dirty = false;
    const h = url.searchParams.get("hostname");
    const t = url.searchParams.get("tag");
    const qq = url.searchParams.get("q");
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    if (h) { setHostname(h); dirty = true; }
    if (t) { setTag(t); dirty = true; }
    if (qq) { setQ(qq); dirty = true; }
    if (from || to) {
      setRangeKey("custom");
      if (from) setCustomFrom(from.slice(0, 16));
      if (to)   setCustomTo(to.slice(0, 16));
      dirty = true;
    }
    if (dirty) setAutoSearchPending(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    if (!autoSearchPending) return;
    setAutoSearchPending(false);
    runSearch(false);
  }, [autoSearchPending, runSearch]);

  return (
    <PageShell title={labels.title} subtitle={labels.subtitle}>
      {error && <ErrorBanner message={`${labels.error}: ${error}`} onRetry={() => runSearch(false)} />}

      {/* Saved queries strip */}
      {saved.length > 0 && (
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center", marginBottom: "12px" }}>
          <span style={{ fontSize: "10px", letterSpacing: "0.12em", color: "var(--tc-text-muted)", textTransform: "uppercase", display: "flex", alignItems: "center", gap: "4px", marginRight: "4px" }}>
            <Bookmark size={11} /> {labels.saved}
          </span>
          {saved.map(sq => (
            <span key={sq.id} style={{
              display: "inline-flex", alignItems: "center", gap: "4px",
              padding: "4px 4px 4px 10px", borderRadius: "var(--tc-radius-md)",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-input)",
              fontSize: "11px", color: "var(--tc-text)",
            }}>
              <button
                onClick={() => applySaved(sq)}
                title={sq.name}
                style={{ background: "none", border: "none", cursor: "pointer", color: "inherit", font: "inherit", padding: 0 }}
              >
                {sq.name}
              </button>
              <button
                onClick={() => deleteSaved(sq.id)}
                title={labels.delete}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "2px 4px" }}
              >
                <Trash2 size={11} />
              </button>
            </span>
          ))}
        </div>
      )}

      {/* Filters card */}
      <NeuCard style={{ padding: "16px", marginBottom: "16px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          {/* Row 1: hostname + tag */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            <FieldDatalist
              icon={<Server size={13} color="var(--tc-text-muted)" />}
              label={labels.hostname}
              value={hostname}
              onChange={setHostname}
              placeholder="srv-app-01"
              options={assetHostnames}
              listId="hunt-host-options"
            />
            <FieldSelect
              icon={<TagIcon size={13} color="var(--tc-text-muted)" />}
              label={labels.tag}
              value={tag}
              onChange={setTag}
              options={[{ value: "", label: "—" }, ...TAG_PRESETS.map(t => ({ value: t, label: t }))]}
            />
          </div>

          {/* Row 2: time range presets */}
          <div>
            <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
              <Clock size={12} /> {labels.range}
            </div>
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
              {RANGE_PRESETS.map(p => {
                const active = rangeKey === p.key;
                return (
                  <button key={p.key} onClick={() => setRangeKey(p.key)} style={{
                    padding: "6px 12px", borderRadius: "var(--tc-radius-md)", fontSize: "11px", fontWeight: 600,
                    border: `1px solid ${active ? "rgba(48,128,208,0.3)" : "var(--tc-input)"}`,
                    background: active ? "rgba(48,128,208,0.08)" : "var(--tc-surface-alt)",
                    color: active ? "var(--tc-blue)" : "var(--tc-text-muted)",
                    cursor: "pointer", fontFamily: "inherit",
                  }}>
                    {locale === "fr" ? p.labelFr : p.labelEn}
                  </button>
                );
              })}
              <button onClick={() => setRangeKey("custom")} style={{
                padding: "6px 12px", borderRadius: "var(--tc-radius-md)", fontSize: "11px", fontWeight: 600,
                border: `1px solid ${rangeKey === "custom" ? "rgba(48,128,208,0.3)" : "var(--tc-input)"}`,
                background: rangeKey === "custom" ? "rgba(48,128,208,0.08)" : "var(--tc-surface-alt)",
                color: rangeKey === "custom" ? "var(--tc-blue)" : "var(--tc-text-muted)",
                cursor: "pointer", fontFamily: "inherit",
              }}>
                {labels.custom}
              </button>
            </div>
            {rangeKey === "custom" && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginTop: "8px" }}>
                <FieldInput type="datetime-local" label={labels.from} value={customFrom} onChange={setCustomFrom} />
                <FieldInput type="datetime-local" label={labels.to}   value={customTo}   onChange={setCustomTo} />
              </div>
            )}
          </div>

          {/* Row 3: free-text q */}
          <FieldInput
            icon={<Search size={13} color="var(--tc-text-muted)" />}
            label={labels.freeText}
            value={q}
            onChange={setQ}
            placeholder="failed password, 10.0.0.5, powershell..."
          />

          {/* Actions */}
          <div style={{ display: "flex", gap: "8px", alignItems: "center", borderTop: "1px solid var(--tc-border-light)", paddingTop: "12px" }}>
            <ChromeButton onClick={() => runSearch(false)} variant="primary">
              <Search size={13} /> {labels.search}
            </ChromeButton>
            <ChromeButton onClick={reset} variant="glass">
              <X size={13} /> {labels.reset}
            </ChromeButton>
            <ChromeButton onClick={saveCurrent} variant="glass" disabled={savingBusy}>
              <Bookmark size={13} /> {labels.save}
            </ChromeButton>
            {hasSearched && (
              <ChromeButton onClick={() => runSearch(false)} variant="glass">
                <RefreshCw size={13} />
              </ChromeButton>
            )}
            <div style={{ marginLeft: "auto", display: "flex", gap: "12px", fontSize: "11px", color: "var(--tc-text-muted)", alignItems: "center" }}>
              {scannedChunks !== null && (
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <Database size={11} /> {scannedChunks} {labels.chunks}
                </span>
              )}
              {hasSearched && (
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <Filter size={11} /> {logs.length}{nextCursor ? "+" : ""} {labels.results}
                </span>
              )}
            </div>
          </div>
        </div>
      </NeuCard>

      {/* Results */}
      {!hasSearched && !loading && (
        <NeuCard><div style={{ textAlign: "center", padding: "48px", color: "var(--tc-text-muted)", fontSize: "13px" }}>{labels.runQuery}</div></NeuCard>
      )}

      {loading && logs.length === 0 && (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.loading}</div></NeuCard>
      )}

      {hasSearched && !loading && logs.length === 0 && (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.noResults}</div></NeuCard>
      )}

      {logs.length > 0 && (
        <NeuCard style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", borderBottom: "1px solid var(--tc-border)" }}>
                <th style={thStyle()}></th>
                <th style={thStyle()}>{labels.time}</th>
                <th style={thStyle()}>{labels.host}</th>
                <th style={thStyle()}>{labels.tag}</th>
                <th style={thStyle()}>{labels.msg}</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => {
                const isOpen = expanded === log.id;
                const preview = previewMessage(log.data || {});
                return (
                  <React.Fragment key={log.id}>
                    <tr
                      onClick={() => setExpanded(isOpen ? null : log.id)}
                      style={{
                        cursor: "pointer",
                        borderBottom: "1px solid var(--tc-border-light)",
                        background: isOpen ? "var(--tc-surface-alt)" : "transparent",
                      }}
                    >
                      <td style={{ padding: "6px 10px", width: "24px" }}>
                        {isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                      </td>
                      <td style={{ padding: "6px 10px", fontFamily: "monospace", color: "var(--tc-text-muted)", whiteSpace: "nowrap" }}>
                        {new Date(log.time).toLocaleString(locale === "fr" ? "fr-FR" : "en-US")}
                      </td>
                      <td style={{ padding: "6px 10px", fontFamily: "monospace", color: "var(--tc-blue)", whiteSpace: "nowrap" }}>
                        {log.hostname || "—"}
                      </td>
                      <td style={{ padding: "6px 10px", color: "var(--tc-text-muted)", whiteSpace: "nowrap" }}>
                        {log.tag || "—"}
                      </td>
                      <td style={{ padding: "6px 10px", color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "0" }}>
                        {preview}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr style={{ background: "var(--tc-surface-alt)", borderBottom: "1px solid var(--tc-border)" }}>
                        <td colSpan={5} style={{ padding: "12px 16px" }}>
                          <div style={{ fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase", color: "var(--tc-text-muted)", marginBottom: "6px" }}>{labels.raw}</div>
                          <pre style={{
                            margin: 0, padding: "10px", borderRadius: "var(--tc-radius-sm)",
                            background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                            fontSize: "11px", color: "var(--tc-text)", overflow: "auto", maxHeight: "320px",
                            fontFamily: "monospace",
                          }}>
                            {JSON.stringify(log.data, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
          {nextCursor && (
            <div style={{ padding: "12px", textAlign: "center", borderTop: "1px solid var(--tc-border)" }}>
              <ChromeButton onClick={() => runSearch(true)} variant="glass" disabled={loading}>
                {loading ? labels.loading : labels.loadMore}
              </ChromeButton>
            </div>
          )}
        </NeuCard>
      )}
    </PageShell>
  );
}

function thStyle(): React.CSSProperties {
  return {
    padding: "8px 10px", textAlign: "left", fontSize: "10px",
    letterSpacing: "0.12em", textTransform: "uppercase",
    color: "var(--tc-text-muted)", fontWeight: 600,
  };
}

function FieldInput({
  label, value, onChange, placeholder, icon, type = "text",
}: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; icon?: React.ReactNode; type?: string;
}) {
  return (
    <div>
      <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
        {icon} {label}
      </div>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%", padding: "8px 12px",
          background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)",
          fontSize: "13px", fontFamily: "inherit", outline: "none",
          boxSizing: "border-box",
        }}
      />
    </div>
  );
}

function FieldDatalist({
  label, value, onChange, placeholder, icon, options, listId,
}: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; icon?: React.ReactNode;
  options: string[]; listId: string;
}) {
  return (
    <div>
      <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
        {icon} {label}
        {options.length > 0 && (
          <span style={{ color: "var(--tc-text-muted)", fontSize: "9px", fontWeight: 400 }}>
            · {options.length}
          </span>
        )}
      </div>
      <input
        type="text"
        list={listId}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%", padding: "8px 12px",
          background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)",
          fontSize: "13px", fontFamily: "inherit", outline: "none",
          boxSizing: "border-box",
        }}
      />
      <datalist id={listId}>
        {options.map(o => <option key={o} value={o} />)}
      </datalist>
    </div>
  );
}

function FieldSelect({
  label, value, onChange, options, icon,
}: {
  label: string; value: string; onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>; icon?: React.ReactNode;
}) {
  return (
    <div>
      <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
        {icon} {label}
      </div>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          width: "100%", padding: "8px 12px",
          background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)",
          fontSize: "13px", fontFamily: "inherit", outline: "none",
          boxSizing: "border-box",
        }}
      >
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { PageShell } from "@/components/chrome/PageShell";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import {
  Search, RefreshCw, X, Filter, Activity, ShieldAlert,
  CheckCircle2, AlertCircle, ChevronUp, ChevronDown, Grid3x3, ExternalLink,
  ShieldOff,
} from "lucide-react";

type Rule = {
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
  updated_at: string | null;
  fire_count_7d: number;
  fire_count_30d: number;
  last_fire_at: string | null;
  fp_count_7d: number;
  distinct_hosts_7d: number;
  top_hostname_7d: string | null;
};

const LEVEL_COLOR: Record<string, { bg: string; color: string; border: string }> = {
  critical: { bg: "rgba(232,64,64,0.10)", color: "#e84040", border: "rgba(232,64,64,0.30)" },
  high:     { bg: "rgba(208,112,32,0.10)", color: "#d07020", border: "rgba(208,112,32,0.30)" },
  medium:   { bg: "rgba(208,144,32,0.10)", color: "#d09020", border: "rgba(208,144,32,0.30)" },
  low:      { bg: "rgba(48,128,208,0.10)", color: "#3080d0", border: "rgba(48,128,208,0.30)" },
  informational: { bg: "var(--tc-input)", color: "var(--tc-text-muted)", border: "var(--tc-input)" },
};

type SortKey = "title" | "level" | "fire_count_7d" | "fire_count_30d" | "last_fire_at" | "logsource";

export default function SigmaRulesPage() {
  const router = useRouter();
  const locale = useLocale();
  const labels = useMemo(() => ({
    title:    locale === "fr" ? "Règles de détection" : "Detection rules",
    subtitle: locale === "fr"
      ? "Format Sigma — règles compilées en mémoire, mises à jour à chaque cycle."
      : "Sigma format — rules compiled in memory, refreshed every cycle.",
    search:   locale === "fr" ? "Rechercher (titre, id, tag)..." : "Search (title, id, tag)...",
    refresh:  locale === "fr" ? "Actualiser"   : "Refresh",
    reset:    locale === "fr" ? "Réinitialiser": "Reset",
    coverage: locale === "fr" ? "Couverture MITRE" : "MITRE coverage",
    total:    locale === "fr" ? "règles"        : "rules",
    fire7:    locale === "fr" ? "7j"            : "7d",
    fire30:   locale === "fr" ? "30j"           : "30d",
    fp:       locale === "fr" ? "FP"            : "FP",
    hosts:    locale === "fr" ? "hôtes"         : "hosts",
    lastFire: locale === "fr" ? "Dernier match" : "Last fire",
    never:    locale === "fr" ? "jamais"        : "never",
    noResults:locale === "fr" ? "Aucune règle ne correspond aux filtres." : "No rule matches the filters.",
    loading:  locale === "fr" ? "Chargement..." : "Loading...",
    error:    locale === "fr" ? "Erreur"        : "Error",
    cold:     locale === "fr" ? "froide"        : "cold",
    noisy:    locale === "fr" ? "bruyante"      : "noisy",
    enabled:  locale === "fr" ? "active"        : "enabled",
    disabled: locale === "fr" ? "désactivée"    : "disabled",
    columnTitle:   locale === "fr" ? "Titre" : "Title",
    columnSrc:     locale === "fr" ? "Source" : "Source",
    columnLevel:   locale === "fr" ? "Sévérité" : "Severity",
    columnState:   locale === "fr" ? "État" : "State",
  }), [locale]);

  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState("");
  const [logsourceFilter, setLogsourceFilter] = useState("");
  const [stateFilter, setStateFilter] = useState<"all" | "enabled" | "disabled" | "cold" | "noisy">("all");
  const [sortKey, setSortKey] = useState<SortKey>("fire_count_7d");
  const [sortDesc, setSortDesc] = useState(true);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch("/api/tc/sigma/rules");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setRules(Array.isArray(json.rules) ? json.rules : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const logsourceOptions = useMemo(() => {
    const set = new Set<string>();
    rules.forEach(r => {
      const src = r.logsource_product || r.logsource_category || "—";
      set.add(src);
    });
    return Array.from(set).sort();
  }, [rules]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rules.filter(r => {
      if (q) {
        const hay = `${r.id} ${r.title} ${(r.tags || []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (levelFilter && r.level !== levelFilter) return false;
      if (logsourceFilter) {
        const src = r.logsource_product || r.logsource_category || "—";
        if (src !== logsourceFilter) return false;
      }
      if (stateFilter === "enabled" && !r.enabled) return false;
      if (stateFilter === "disabled" && r.enabled) return false;
      if (stateFilter === "cold" && (r.fire_count_30d > 0 || !r.enabled)) return false;
      if (stateFilter === "noisy" && r.fire_count_7d < 50) return false;
      return true;
    });
  }, [rules, search, levelFilter, logsourceFilter, stateFilter]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    arr.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "title": cmp = a.title.localeCompare(b.title); break;
        case "level":
          cmp = (order[a.level] ?? 5) - (order[b.level] ?? 5); break;
        case "fire_count_7d": cmp = a.fire_count_7d - b.fire_count_7d; break;
        case "fire_count_30d": cmp = a.fire_count_30d - b.fire_count_30d; break;
        case "last_fire_at": cmp = (a.last_fire_at || "").localeCompare(b.last_fire_at || ""); break;
        case "logsource":
          cmp = (a.logsource_product || a.logsource_category || "")
            .localeCompare(b.logsource_product || b.logsource_category || "");
          break;
      }
      return sortDesc ? -cmp : cmp;
    });
    return arr;
  }, [filtered, sortKey, sortDesc]);

  const toggleSort = (k: SortKey) => {
    if (sortKey === k) setSortDesc(!sortDesc);
    else { setSortKey(k); setSortDesc(true); }
  };

  const reset = () => {
    setSearch(""); setLevelFilter(""); setLogsourceFilter(""); setStateFilter("all");
  };

  const counters = useMemo(() => ({
    total: rules.length,
    enabled: rules.filter(r => r.enabled).length,
    fired7d: rules.filter(r => r.fire_count_7d > 0).length,
    cold: rules.filter(r => r.enabled && r.fire_count_30d === 0).length,
    noisy: rules.filter(r => r.fire_count_7d >= 50).length,
  }), [rules]);

  return (
    <PageShell title={labels.title} subtitle={labels.subtitle}
      right={
        <div style={{ display: "flex", gap: "6px" }}>
          <ChromeButton onClick={() => router.push("/sigma/audit")} variant="glass">
            <ShieldOff size={13} /> {locale === "fr" ? "Audit" : "Audit"}
          </ChromeButton>
          <ChromeButton onClick={() => router.push("/sigma/coverage")} variant="glass">
            <Grid3x3 size={13} /> {labels.coverage}
          </ChromeButton>
        </div>
      }
    >
      {error && <ErrorBanner message={`${labels.error}: ${error}`} onRetry={load} />}

      {/* Counter strip */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "12px" }}>
        <Counter label={labels.total} value={counters.total} />
        <Counter label={labels.enabled} value={counters.enabled} color="#30a050" />
        <Counter label={labels.fire7} value={counters.fired7d} icon={<Activity size={11} />} />
        <Counter label={labels.cold} value={counters.cold} color="var(--tc-text-muted)" />
        <Counter label={labels.noisy} value={counters.noisy} icon={<AlertCircle size={11} />} color="#d07020" />
      </div>

      {/* Filters */}
      <NeuCard style={{ padding: "12px", marginBottom: "16px" }}>
        <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: "240px", display: "flex", alignItems: "center", gap: "8px",
            background: "var(--tc-input)", border: "1px solid var(--tc-border)",
            borderRadius: "var(--tc-radius-md)", padding: "8px 12px" }}>
            <Search size={13} color="var(--tc-text-muted)" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder={labels.search}
              style={{ flex: 1, background: "none", border: "none", outline: "none",
                color: "var(--tc-text)", fontSize: "13px", fontFamily: "inherit" }} />
            {search && (
              <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                <X size={13} color="var(--tc-text-muted)" />
              </button>
            )}
          </div>

          <select value={levelFilter} onChange={e => setLevelFilter(e.target.value)} style={selectStyle()}>
            <option value="">— {labels.columnLevel}</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="informational">informational</option>
          </select>

          <select value={logsourceFilter} onChange={e => setLogsourceFilter(e.target.value)} style={selectStyle()}>
            <option value="">— {labels.columnSrc}</option>
            {logsourceOptions.map(o => <option key={o} value={o}>{o}</option>)}
          </select>

          <select value={stateFilter}
            onChange={e => setStateFilter(e.target.value as typeof stateFilter)}
            style={selectStyle()}>
            <option value="all">— {labels.columnState}</option>
            <option value="enabled">{labels.enabled}</option>
            <option value="disabled">{labels.disabled}</option>
            <option value="cold">{labels.cold}</option>
            <option value="noisy">{labels.noisy}</option>
          </select>

          <ChromeButton onClick={reset} variant="glass"><Filter size={12} /> {labels.reset}</ChromeButton>
          <ChromeButton onClick={load} variant="glass"><RefreshCw size={12} /></ChromeButton>
        </div>
      </NeuCard>

      {/* Table */}
      {loading ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.loading}</div></NeuCard>
      ) : sorted.length === 0 ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.noResults}</div></NeuCard>
      ) : (
        <NeuCard style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", borderBottom: "1px solid var(--tc-border)" }}>
                <Th label={labels.columnTitle} sortKey="title" active={sortKey} desc={sortDesc} onClick={toggleSort} />
                <Th label={labels.columnSrc} sortKey="logsource" active={sortKey} desc={sortDesc} onClick={toggleSort} />
                <Th label={labels.columnLevel} sortKey="level" active={sortKey} desc={sortDesc} onClick={toggleSort} center />
                <Th label={labels.fire7} sortKey="fire_count_7d" active={sortKey} desc={sortDesc} onClick={toggleSort} center />
                <Th label={labels.fire30} sortKey="fire_count_30d" active={sortKey} desc={sortDesc} onClick={toggleSort} center />
                <Th label={labels.fp} center />
                <Th label={labels.hosts} center />
                <Th label={labels.lastFire} sortKey="last_fire_at" active={sortKey} desc={sortDesc} onClick={toggleSort} />
              </tr>
            </thead>
            <tbody>
              {sorted.map(r => {
                const lvlColors = LEVEL_COLOR[r.level] || LEVEL_COLOR.informational;
                return (
                  <tr key={r.id}
                    onClick={() => router.push(`/sigma/${encodeURIComponent(r.id)}`)}
                    style={{ cursor: "pointer", borderBottom: "1px solid var(--tc-border-light)",
                      opacity: r.enabled ? 1 : 0.55 }}>
                    <td style={tdStyle()}>
                      <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                        <span style={{ color: "var(--tc-text)", fontWeight: 500 }}>{r.title}</span>
                        <span style={{ color: "var(--tc-text-muted)", fontSize: "10px", fontFamily: "monospace" }}>{r.id}</span>
                      </div>
                    </td>
                    <td style={{ ...tdStyle(), color: "var(--tc-text-muted)", whiteSpace: "nowrap" }}>
                      {r.logsource_product || r.logsource_category || "—"}
                    </td>
                    <td style={{ ...tdStyle(), textAlign: "center" }}>
                      <span style={{
                        display: "inline-block", padding: "2px 8px", borderRadius: "var(--tc-radius-sm)",
                        background: lvlColors.bg, color: lvlColors.color,
                        border: `1px solid ${lvlColors.border}`,
                        fontSize: "10px", fontWeight: 700, textTransform: "uppercase",
                      }}>
                        {r.level}
                      </span>
                    </td>
                    <td style={{ ...tdStyle(), textAlign: "center",
                      color: r.fire_count_7d >= 50 ? "#d07020" : r.fire_count_7d > 0 ? "var(--tc-text)" : "var(--tc-text-muted)",
                      fontWeight: r.fire_count_7d > 0 ? 600 : 400, fontFamily: "monospace" }}>
                      {r.fire_count_7d}
                    </td>
                    <td style={{ ...tdStyle(), textAlign: "center", color: "var(--tc-text-muted)", fontFamily: "monospace" }}>
                      {r.fire_count_30d}
                    </td>
                    <td style={{ ...tdStyle(), textAlign: "center",
                      color: r.fp_count_7d > 0 ? "var(--tc-amber)" : "var(--tc-text-muted)", fontFamily: "monospace" }}>
                      {r.fp_count_7d}
                    </td>
                    <td style={{ ...tdStyle(), textAlign: "center", color: "var(--tc-text-muted)", fontFamily: "monospace" }}>
                      {r.distinct_hosts_7d}
                    </td>
                    <td style={{ ...tdStyle(), color: "var(--tc-text-muted)", whiteSpace: "nowrap", fontSize: "11px" }}>
                      {r.last_fire_at
                        ? new Date(r.last_fire_at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US")
                        : labels.never}
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

function Th({ label, sortKey, active, desc, onClick, center }: {
  label: string; sortKey?: SortKey; active?: SortKey;
  desc?: boolean; onClick?: (k: SortKey) => void; center?: boolean;
}) {
  const sortable = !!sortKey && !!onClick;
  return (
    <th onClick={() => sortable && onClick!(sortKey!)}
      style={{
        padding: "8px 12px", textAlign: center ? "center" : "left",
        fontSize: "10px", letterSpacing: "0.12em", textTransform: "uppercase",
        color: "var(--tc-text-muted)", fontWeight: 600,
        cursor: sortable ? "pointer" : "default", userSelect: "none",
      }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
        {label}
        {sortable && active === sortKey && (
          desc ? <ChevronDown size={10} /> : <ChevronUp size={10} />
        )}
      </span>
    </th>
  );
}

function Counter({ label, value, color, icon }: {
  label: string; value: number; color?: string; icon?: React.ReactNode;
}) {
  return (
    <div style={{
      padding: "8px 12px", borderRadius: "var(--tc-radius-md)",
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-input)",
      display: "flex", alignItems: "center", gap: "8px", fontSize: "12px",
    }}>
      {icon && <span style={{ color: color || "var(--tc-text-muted)" }}>{icon}</span>}
      <span style={{ fontWeight: 800, fontSize: "16px", color: color || "var(--tc-text)" }}>{value}</span>
      <span style={{ color: "var(--tc-text-muted)", textTransform: "uppercase", fontSize: "10px", letterSpacing: "0.08em" }}>{label}</span>
    </div>
  );
}

function tdStyle(): React.CSSProperties {
  return { padding: "10px 12px", fontSize: "12px" };
}

function selectStyle(): React.CSSProperties {
  return {
    padding: "8px 12px",
    background: "var(--tc-input)", border: "1px solid var(--tc-border)",
    borderRadius: "var(--tc-radius-md)", color: "var(--tc-text)",
    fontSize: "12px", fontFamily: "inherit", outline: "none",
  };
}

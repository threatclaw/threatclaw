"use client";
// Dense, virtualised inventory surface (lot 4) — table (default) / list modes,
// filter / sort / group, facets, multi-select bar and a detail drawer. Logic
// lives in lib/assetPipeline.ts; this file is the React shell. Reuses the
// parent's add/edit modal + merge/trash handlers via callbacks.
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  Plus, Search, X, Check, Filter, ArrowUpDown, Group, Columns3, List, Table2,
  ChevronDown, ChevronRight, Loader2, MoreHorizontal, Server, Network, Monitor,
  HelpCircle, ExternalLink, Pencil, Copy, Trash2,
} from "lucide-react";
import type { Asset } from "@/lib/asset-shared";
import type { Locale } from "@/lib/i18n";
import { formatRelative } from "@/lib/relative-time";
import {
  assetType, sourceBucket, critBucket, userTagLabels, passes, sortAssets,
  groupAssets, EMPTY_FILTERS,
  type AssetType, type SourceBucket, type CritBucket, type Filters,
  type SortKey, type SortDir, type GroupKey,
} from "@/lib/assetPipeline";

interface TagEntity { id: number; label: string; color: string; usage_count?: number }

interface Props {
  assets: Asset[];
  loading: boolean;
  locale: Locale;
  onEdit: (a: Asset) => void;
  onMergeIds: (ids: string[]) => void;
  onTrash: (a: Asset) => void;
  onTrashIds: (ids: string[]) => void;
  onRefresh: () => void;
}

// ── persisted view-state ──────────────────────────────────────────────────
interface ViewState {
  mode: "table" | "list";
  sort: { key: SortKey; dir: SortDir };
  group: GroupKey;
  type: AssetType | "all";
  filters: Filters;
  cols: Record<string, boolean>;
}
const LS_KEY = "tc_asset_view_state";
const DEFAULT_VIEW: ViewState = {
  mode: "table",
  sort: { key: "name", dir: "asc" },
  group: "type", // never open on thousands of flat rows
  type: "all",
  filters: EMPTY_FILTERS,
  cols: { ip: true, os: true, crit: true, source: true, tags: true },
};

const fr = (l: Locale) => l === "fr";
const TYPE_ICON: Record<AssetType, React.ComponentType<{ size?: number }>> = {
  srv: Server, net: Network, pc: Monitor, unk: HelpCircle,
};
const TYPE_COLOR: Record<AssetType, string> = {
  srv: "var(--tc-blue)", net: "var(--tc-red)", pc: "var(--tc-green)", unk: "var(--tc-text-muted)",
};
const CRIT_DOT: Record<CritBucket, string> = {
  haut: "var(--tc-red)", moyen: "#d09020", bas: "var(--tc-green)",
};
function typeLabel(t: AssetType, l: Locale): string {
  const m = fr(l)
    ? { srv: "Serveur", pc: "Poste client", net: "Équipement réseau", unk: "Inconnu" }
    : { srv: "Server", pc: "Workstation", net: "Network device", unk: "Unknown" };
  return m[t];
}
function sourceLabel(s: SourceBucket, l: Locale): string {
  const m = fr(l)
    ? { agent: "Agent osquery", syslog: "Syslog", passif: "Réseau passif" }
    : { agent: "osquery agent", syslog: "Syslog", passif: "Passive network" };
  return m[s];
}
function critLabel(c: CritBucket, l: Locale): string {
  const m = fr(l) ? { haut: "Haute", moyen: "Moyenne", bas: "Basse" } : { haut: "High", moyen: "Medium", bas: "Low" };
  return m[c];
}

type FlatRow =
  | { kind: "group"; label: string; count: number }
  | { kind: "asset"; asset: Asset };

export default function InventoryView(props: Props) {
  const { assets, loading, locale, onEdit, onMergeIds, onTrash, onTrashIds, onRefresh } = props;
  const l = locale;

  const [view, setView] = useState<ViewState>(DEFAULT_VIEW);
  const [hydrated, setHydrated] = useState(false);
  const [search, setSearch] = useState(""); // not persisted
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({}); // session-local
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [drawer, setDrawer] = useState<Asset | null>(null);
  const [openMenu, setOpenMenu] = useState<null | "filter" | "sort" | "group" | "cols">(null);
  const [tags, setTags] = useState<TagEntity[]>([]);

  // Hydrate: localStorage first (instant, no flash), then the server (source of
  // truth across devices — single operator per instance, model B+).
  useEffect(() => {
    const merge = (v: Partial<ViewState>) => setView(prev => ({
      ...DEFAULT_VIEW, ...prev, ...v,
      filters: { ...EMPTY_FILTERS, ...(v.filters || {}) },
      cols: { ...DEFAULT_VIEW.cols, ...(v.cols || {}) },
    }));
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (raw) merge(JSON.parse(raw));
    } catch { /* ignore */ }
    let cancelled = false;
    fetch("/api/tc/ui-state/asset_view_state")
      .then(r => r.json())
      .then(d => { if (!cancelled && d && d.value) merge(d.value); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setHydrated(true); });
    return () => { cancelled = true; };
  }, []);
  // Persist (debounced) after hydration: localStorage cache + server.
  useEffect(() => {
    if (!hydrated) return;
    const t = setTimeout(() => {
      try { localStorage.setItem(LS_KEY, JSON.stringify(view)); } catch { /* ignore */ }
      fetch("/api/tc/ui-state/asset_view_state", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: view }),
      }).catch(() => {});
    }, 500);
    return () => clearTimeout(t);
  }, [view, hydrated]);

  // tag palette for the facet panel + colour lookups.
  useEffect(() => {
    fetch("/api/tc/tags").then(r => r.json()).then(d => setTags(d.tags || [])).catch(() => {});
  }, [assets]);

  const patch = (p: Partial<ViewState>) => setView(v => ({ ...v, ...p }));
  const toggleFacet = (facet: keyof Filters, val: string) => setView(v => {
    const arr = v.filters[facet] as string[];
    const next = arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val];
    return { ...v, filters: { ...v.filters, [facet]: next } };
  });

  // Esc closes drawer / menus.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setDrawer(null); setOpenMenu(null); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // ── data pipeline ────────────────────────────────────────────────────────
  const typeCounts = useMemo(() => {
    const c: Record<string, number> = { all: assets.length, srv: 0, pc: 0, net: 0, unk: 0 };
    for (const a of assets) c[assetType(a.category)]++;
    return c;
  }, [assets]);

  const osOptions = useMemo(
    () => Array.from(new Set(assets.map(a => a.os).filter(Boolean) as string[])).sort(),
    [assets],
  );

  const filtered = useMemo(
    () => assets.filter(a => passes(a, view.type, view.filters, search)),
    [assets, view.type, view.filters, search],
  );
  const groups = useMemo(
    () => groupAssets(
      sortAssets(filtered, view.sort.key, view.sort.dir),
      view.group,
      (t) => typeLabel(t, l),
      (s) => sourceLabel(s, l),
      fr(l) ? "(sans tag)" : "(untagged)",
    ),
    [filtered, view.sort, view.group, l],
  );

  // flatten groups → virtual rows (skip collapsed groups' assets).
  const rows: FlatRow[] = useMemo(() => {
    const out: FlatRow[] = [];
    for (const [label, items] of groups) {
      if (label !== "") {
        out.push({ kind: "group", label, count: items.length });
        if (collapsed[label]) continue;
      }
      for (const a of items) out.push({ kind: "asset", asset: a });
    }
    return out;
  }, [groups, collapsed]);

  const parentRef = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i) => (rows[i].kind === "group" ? 34 : view.mode === "table" ? 40 : 46),
    overscan: 14,
  });

  const activeFilterCount = Object.values(view.filters).reduce((n, a) => n + a.length, 0);
  const visibleCols = view.cols;

  // table grid template (checkbox, name, [ip], [os], [crit], [source], [tags], seen)
  const gridCols = [
    "28px", "minmax(160px,1.4fr)",
    visibleCols.ip ? "minmax(110px,0.9fr)" : "",
    visibleCols.os ? "minmax(120px,1fr)" : "",
    visibleCols.crit ? "100px" : "",
    visibleCols.source ? "130px" : "",
    visibleCols.tags ? "minmax(120px,1.2fr)" : "",
    "120px",
  ].filter(Boolean).join(" ");

  const allVisibleIds = rows.filter(r => r.kind === "asset").map(r => (r as { asset: Asset }).asset.id);
  const allSelected = allVisibleIds.length > 0 && allVisibleIds.every(id => selected.has(id));
  const toggleSel = (id: string) => setSelected(s => {
    const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n;
  });
  const toggleAll = () => setSelected(s => {
    if (allSelected) return new Set();
    return new Set(allVisibleIds);
  });

  // ── small UI atoms ─────────────────────────────────────────────────────
  const ctrlBtn = (active: boolean): React.CSSProperties => ({
    display: "inline-flex", alignItems: "center", gap: "6px", padding: "8px 11px",
    fontSize: "12px", fontFamily: "inherit", cursor: "pointer", borderRadius: "var(--tc-radius-sm)",
    background: active ? "rgba(75,142,240,0.14)" : "var(--tc-input)",
    color: active ? "#cfe0ff" : "var(--tc-text-sec)",
    border: `1px solid ${active ? "rgba(75,142,240,0.5)" : "var(--tc-border)"}`,
  });
  const menuPanel: React.CSSProperties = {
    position: "absolute", top: "40px", left: 0, zIndex: 40, minWidth: "210px",
    background: "var(--tc-bg2, var(--tc-input))", border: "1px solid var(--tc-border)",
    borderRadius: "var(--tc-radius-md)", padding: "6px", boxShadow: "0 14px 40px rgba(0,0,0,0.5)",
  };
  const menuItem = (on: boolean): React.CSSProperties => ({
    display: "flex", alignItems: "center", gap: "9px", padding: "8px 10px", fontSize: "12px",
    borderRadius: "var(--tc-radius-sm)", cursor: "pointer",
    color: on ? "var(--tc-text)" : "var(--tc-text-sec)",
  });
  const menuSec: React.CSSProperties = {
    fontSize: "9px", letterSpacing: "1.2px", color: "var(--tc-text-muted)", padding: "8px 10px 4px",
    textTransform: "uppercase",
  };

  const tagPill = (label: string, color: string, onClick?: () => void) => (
    <span key={label} onClick={onClick}
      style={{
        display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "10px", fontWeight: 600,
        padding: "2px 8px", borderRadius: "20px", cursor: onClick ? "pointer" : "default",
        color, border: `1px solid ${color}55`, background: `${color}14`,
      }}>
      <span style={{ width: "5px", height: "5px", borderRadius: "50%", background: color }} />
      {label}
    </span>
  );

  // ── bulk tag ─────────────────────────────────────────────────────────────
  const bulkTag = async () => {
    const label = window.prompt(fr(l) ? "Tag à ajouter à la sélection :" : "Tag to add to the selection:");
    if (!label || !label.trim()) return;
    await fetch("/api/tc/assets/bulk-tag", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ asset_ids: Array.from(selected), label: label.trim().toLowerCase() }),
    }).catch(() => {});
    setSelected(new Set());
    onRefresh();
  };

  const SORT_KEYS: { k: SortKey; fr: string; en: string }[] = [
    { k: "name", fr: "Nom", en: "Name" }, { k: "ip", fr: "Adresse IP", en: "IP address" },
    { k: "os", fr: "OS", en: "OS" }, { k: "crit", fr: "Criticité", en: "Criticality" },
    { k: "seen", fr: "Dernière vue", en: "Last seen" },
  ];
  const GROUP_KEYS: { k: GroupKey; fr: string; en: string }[] = [
    { k: "none", fr: "Aucun", en: "None" }, { k: "os", fr: "OS", en: "OS" },
    { k: "tag", fr: "Tag", en: "Tag" }, { k: "subnet", fr: "Sous-réseau /24", en: "Subnet /24" },
    { k: "type", fr: "Type", en: "Type" }, { k: "source", fr: "Source", en: "Source" },
  ];
  const COLS: { k: string; fr: string; en: string }[] = [
    { k: "ip", fr: "IP", en: "IP" }, { k: "os", fr: "OS", en: "OS" },
    { k: "crit", fr: "Criticité", en: "Criticality" }, { k: "source", fr: "Source", en: "Source" },
    { k: "tags", fr: "Tags", en: "Tags" },
  ];
  const sortLbl = SORT_KEYS.find(s => s.k === view.sort.key)!;
  const groupLbl = GROUP_KEYS.find(g => g.k === view.group)!;

  const setSort = (k: SortKey) => patch({
    sort: { key: k, dir: view.sort.key === k && view.sort.dir === "asc" ? "desc" : "asc" },
  });

  return (
    <div onClick={() => setOpenMenu(null)}>
      {/* Type pills */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "14px" }}>
        {(["all", "srv", "pc", "net", "unk"] as const).map(t => {
          const active = view.type === t;
          const label = t === "all" ? (fr(l) ? "TOUS" : "ALL") : typeLabel(t, l);
          return (
            <button key={t} onClick={() => patch({ type: t })} style={{
              ...ctrlBtn(active), fontWeight: t === "all" ? 700 : 600,
              padding: "7px 12px", borderRadius: "8px",
            }}>
              {label} <span style={{ color: active ? "#9cc0ff" : "var(--tc-text-muted)" }}>{typeCounts[t] ?? 0}</span>
            </button>
          );
        })}
      </div>

      {/* Control bar */}
      <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap", marginBottom: "10px", position: "relative" }}>
        <div style={{ flex: 1, minWidth: "200px", display: "flex", alignItems: "center", gap: "9px",
          border: "1px solid var(--tc-border)", background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)", padding: "8px 11px" }}>
          <Search size={13} style={{ color: "var(--tc-text-muted)" }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder={fr(l) ? "Rechercher : nom, IP, hostname, OS, rôle, tag…" : "Search: name, IP, hostname, OS, role, tag…"}
            style={{ flex: 1, border: "none", outline: "none", background: "transparent", color: "var(--tc-text)", fontFamily: "inherit", fontSize: "13px" }} />
        </div>

        {/* Filter */}
        <div style={{ position: "relative" }} onClick={e => e.stopPropagation()}>
          <button style={ctrlBtn(activeFilterCount > 0)} onClick={() => setOpenMenu(m => m === "filter" ? null : "filter")}>
            <Filter size={13} /> {fr(l) ? "Filtrer" : "Filter"} {activeFilterCount > 0 && <span>({activeFilterCount})</span>}
          </button>
          {openMenu === "filter" && (
            <div style={{ ...menuPanel, minWidth: "240px", maxHeight: "60vh", overflow: "auto" }}>
              <div style={menuSec}>SOURCE</div>
              {(["agent", "syslog", "passif"] as SourceBucket[]).map(s => (
                <div key={s} style={menuItem(view.filters.source.includes(s))} onClick={() => toggleFacet("source", s)}>
                  <Cb on={view.filters.source.includes(s)} /> {sourceLabel(s, l)}
                </div>
              ))}
              <div style={menuSec}>{fr(l) ? "CRITICITÉ" : "CRITICALITY"}</div>
              {(["haut", "moyen", "bas"] as CritBucket[]).map(c => (
                <div key={c} style={menuItem(view.filters.crit.includes(c))} onClick={() => toggleFacet("crit", c)}>
                  <Cb on={view.filters.crit.includes(c)} /> {critLabel(c, l)}
                </div>
              ))}
              {tags.length > 0 && <div style={menuSec}>TAG</div>}
              {tags.map(t => (
                <div key={t.id} style={menuItem(view.filters.tag.includes(t.label))} onClick={() => toggleFacet("tag", t.label)}>
                  <Cb on={view.filters.tag.includes(t.label)} />
                  <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: t.color }} /> {t.label}
                </div>
              ))}
              {osOptions.length > 0 && <div style={menuSec}>OS</div>}
              {osOptions.map(o => (
                <div key={o} style={menuItem(view.filters.os.includes(o))} onClick={() => toggleFacet("os", o)}>
                  <Cb on={view.filters.os.includes(o)} /> {o}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Sort */}
        <div style={{ position: "relative" }} onClick={e => e.stopPropagation()}>
          <button style={ctrlBtn(false)} onClick={() => setOpenMenu(m => m === "sort" ? null : "sort")}>
            <ArrowUpDown size={13} /> {fr(l) ? "Trier" : "Sort"} : <b style={{ color: "var(--tc-text)" }}>{fr(l) ? sortLbl.fr : sortLbl.en}</b>
          </button>
          {openMenu === "sort" && (
            <div style={menuPanel}>
              <div style={menuSec}>{fr(l) ? "TRIER PAR" : "SORT BY"}</div>
              {SORT_KEYS.map(s => (
                <div key={s.k} style={menuItem(view.sort.key === s.k)} onClick={() => setSort(s.k)}>
                  <Rd on={view.sort.key === s.k} /> {fr(l) ? s.fr : s.en}
                  {view.sort.key === s.k && <span style={{ marginLeft: "auto", color: "var(--tc-blue)" }}>{view.sort.dir === "asc" ? "↑" : "↓"}</span>}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Group */}
        <div style={{ position: "relative" }} onClick={e => e.stopPropagation()}>
          <button style={ctrlBtn(view.group !== "none")} onClick={() => setOpenMenu(m => m === "group" ? null : "group")}>
            <Group size={13} /> {fr(l) ? "Grouper" : "Group"} : <b style={{ color: "var(--tc-text)" }}>{fr(l) ? groupLbl.fr : groupLbl.en}</b>
          </button>
          {openMenu === "group" && (
            <div style={menuPanel}>
              <div style={menuSec}>{fr(l) ? "GROUPER PAR" : "GROUP BY"}</div>
              {GROUP_KEYS.map(g => (
                <div key={g.k} style={menuItem(view.group === g.k)} onClick={() => { patch({ group: g.k }); setOpenMenu(null); }}>
                  <Rd on={view.group === g.k} /> {fr(l) ? g.fr : g.en}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Columns (table mode) */}
        <div style={{ position: "relative" }} onClick={e => e.stopPropagation()}>
          <button style={ctrlBtn(false)} title={fr(l) ? "Colonnes" : "Columns"} onClick={() => setOpenMenu(m => m === "cols" ? null : "cols")}>
            <Columns3 size={13} />
          </button>
          {openMenu === "cols" && (
            <div style={{ ...menuPanel, left: "auto", right: 0 }}>
              <div style={menuSec}>{fr(l) ? "COLONNES (TABLEAU)" : "COLUMNS (TABLE)"}</div>
              {COLS.map(c => (
                <div key={c.k} style={menuItem(!!view.cols[c.k])}
                  onClick={() => patch({ cols: { ...view.cols, [c.k]: !view.cols[c.k] } })}>
                  <Cb on={!!view.cols[c.k]} /> {fr(l) ? c.fr : c.en}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Mode toggle */}
        <div style={{ display: "flex", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", overflow: "hidden" }}>
          <div onClick={() => patch({ mode: "table" })} style={segStyle(view.mode === "table")}><Table2 size={13} /> {fr(l) ? "Tableau" : "Table"}</div>
          <div onClick={() => patch({ mode: "list" })} style={segStyle(view.mode === "list")}><List size={13} /> {fr(l) ? "Liste" : "List"}</div>
        </div>
      </div>

      {/* Active filter chips */}
      {activeFilterCount > 0 && (
        <div style={{ display: "flex", gap: "7px", flexWrap: "wrap", marginBottom: "10px" }}>
          {(Object.keys(view.filters) as (keyof Filters)[]).flatMap(f =>
            (view.filters[f] as string[]).map(v => {
              const lbl = f === "source" ? sourceLabel(v as SourceBucket, l) : f === "crit" ? critLabel(v as CritBucket, l) : v;
              return (
                <span key={`${f}:${v}`} style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "11px",
                  background: "rgba(75,142,240,0.1)", border: "1px solid rgba(75,142,240,0.35)", color: "#cfe0ff",
                  borderRadius: "6px", padding: "4px 8px" }}>
                  <span style={{ color: "var(--tc-text-muted)" }}>{f}:</span>{lbl}
                  <X size={11} style={{ cursor: "pointer" }} onClick={() => toggleFacet(f, v)} />
                </span>
              );
            }),
          )}
        </div>
      )}

      {/* Table header row (table mode only) */}
      {view.mode === "table" && (
        <div style={{ display: "grid", gridTemplateColumns: gridCols, gap: "10px", padding: "8px 12px",
          borderBottom: "1px solid var(--tc-border)", fontSize: "10px", letterSpacing: "0.06em",
          color: "var(--tc-text-muted)", textTransform: "uppercase" }}>
          <div onClick={toggleAll} style={{ cursor: "pointer" }}><Cb on={allSelected} /></div>
          <Th label={fr(l) ? "Nom" : "Name"} k="name" view={view} setSort={setSort} />
          {visibleCols.ip && <Th label="IP" k="ip" view={view} setSort={setSort} />}
          {visibleCols.os && <Th label="OS" k="os" view={view} setSort={setSort} />}
          {visibleCols.crit && <Th label={fr(l) ? "Criticité" : "Criticality"} k="crit" view={view} setSort={setSort} />}
          {visibleCols.source && <div>Source</div>}
          {visibleCols.tags && <div>Tags</div>}
          <Th label={fr(l) ? "Dernière vue" : "Last seen"} k="seen" view={view} setSort={setSort} />
        </div>
      )}

      {/* Virtualised body */}
      {loading ? (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)" }}>
          <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 8px" }} />
        </div>
      ) : rows.length === 0 ? (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)", fontSize: "12px" }}>
          {fr(l) ? "Aucun asset ne correspond à ces filtres." : "No asset matches these filters."}
        </div>
      ) : (
        <div ref={parentRef} style={{ height: "calc(100vh - 320px)", minHeight: "320px", overflow: "auto", position: "relative" }}>
          <div style={{ height: `${virt.getTotalSize()}px`, position: "relative" }}>
            {virt.getVirtualItems().map(vi => {
              const row = rows[vi.index];
              const style: React.CSSProperties = {
                position: "absolute", top: 0, left: 0, width: "100%",
                transform: `translateY(${vi.start}px)`, height: `${vi.size}px`,
              };
              if (row.kind === "group") {
                const isCol = !!collapsed[row.label];
                return (
                  <div key={vi.key} style={{ ...style, display: "flex", alignItems: "center", gap: "8px", padding: "8px 6px", cursor: "pointer", color: "var(--tc-text-sec)" }}
                    onClick={() => setCollapsed(c => ({ ...c, [row.label]: !c[row.label] }))}>
                    {isCol ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
                    <span style={{ fontSize: "12px", color: "var(--tc-text)" }}>{row.label}</span>
                    <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>· {row.count}</span>
                    <span style={{ flex: 1, height: "1px", background: "var(--tc-border)" }} />
                  </div>
                );
              }
              const a = row.asset;
              return view.mode === "table"
                ? <TableRow key={vi.key} a={a} style={style} grid={gridCols} cols={visibleCols} l={l}
                    sel={selected.has(a.id)} onSel={() => toggleSel(a.id)} onOpen={() => setDrawer(a)} tagPill={tagPill} />
                : <ListRow key={vi.key} a={a} style={style} l={l}
                    sel={selected.has(a.id)} onSel={() => toggleSel(a.id)} onOpen={() => setDrawer(a)} onEdit={onEdit} onTrash={onTrash} tagPill={tagPill} />;
            })}
          </div>
        </div>
      )}

      {/* Selection bar */}
      {selected.size > 0 && (
        <div style={{ position: "fixed", left: "50%", bottom: "24px", transform: "translateX(-50%)", zIndex: 50,
          display: "flex", alignItems: "center", gap: "12px", padding: "11px 16px",
          background: "var(--tc-bg2, var(--tc-input))", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-md)", boxShadow: "0 14px 44px rgba(0,0,0,0.5)" }}>
          <span style={{ fontSize: "12.5px", color: "var(--tc-text)" }}>
            <b style={{ color: "var(--tc-blue)" }}>{selected.size}</b> {fr(l) ? "sélectionné·s" : "selected"}
          </span>
          <button style={ctrlBtn(false)} onClick={bulkTag}><Plus size={12} /> {fr(l) ? "Ajouter un tag" : "Add a tag"}</button>
          <button style={ctrlBtn(false)} onClick={() => { onMergeIds(Array.from(selected)); setSelected(new Set()); }}>{fr(l) ? "Fusionner" : "Merge"}</button>
          <button style={ctrlBtn(false)} onClick={() => { onTrashIds(Array.from(selected)); setSelected(new Set()); }}><Trash2 size={12} /> {fr(l) ? "Corbeille" : "Trash"}</button>
          <button style={{ ...ctrlBtn(false), background: "transparent" }} onClick={() => setSelected(new Set())}>{fr(l) ? "Annuler" : "Cancel"}</button>
        </div>
      )}

      {/* Drawer */}
      {drawer && (
        <>
          <div onClick={() => setDrawer(null)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)", zIndex: 60 }} />
          <div role="dialog" aria-label={drawer.name} style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: "380px", maxWidth: "90vw",
            background: "var(--tc-bg2, var(--tc-bg))", borderLeft: "1px solid var(--tc-border)", zIndex: 61, padding: "22px", overflow: "auto",
            boxShadow: "-24px 0 60px rgba(0,0,0,0.5)" }}>
            <Drawer a={drawer} l={l} tagPill={tagPill}
              onClose={() => setDrawer(null)}
              onEdit={() => { onEdit(drawer); setDrawer(null); }}
              onTrash={() => { onTrash(drawer); setDrawer(null); }}
              onMarkDup={() => { onMergeIds([drawer.id]); setDrawer(null); }} />
          </div>
        </>
      )}
    </div>
  );
}

// ── sub-components / atoms ───────────────────────────────────────────────
function Cb({ on }: { on: boolean }) {
  return (
    <span style={{ width: "14px", height: "14px", borderRadius: "4px", flex: "none", display: "flex", alignItems: "center", justifyContent: "center",
      border: `1.5px solid ${on ? "var(--tc-blue)" : "var(--tc-border)"}`, background: on ? "var(--tc-blue)" : "transparent" }}>
      {on && <Check size={10} color="#fff" />}
    </span>
  );
}
function Rd({ on }: { on: boolean }) {
  return (
    <span style={{ width: "13px", height: "13px", borderRadius: "50%", flex: "none",
      border: `1.5px solid ${on ? "var(--tc-blue)" : "var(--tc-border)"}`,
      background: on ? "radial-gradient(circle, var(--tc-blue) 0 4px, transparent 5px)" : "transparent" }} />
  );
}
function segStyle(on: boolean): React.CSSProperties {
  return {
    display: "flex", alignItems: "center", gap: "6px", padding: "8px 12px", fontSize: "12px", cursor: "pointer",
    background: on ? "rgba(75,142,240,0.16)" : "transparent", color: on ? "#cfe0ff" : "var(--tc-text-muted)",
  };
}
function Th({ label, k, view, setSort }: { label: string; k: SortKey; view: ViewState; setSort: (k: SortKey) => void }) {
  const on = view.sort.key === k;
  return (
    <div onClick={() => setSort(k)} style={{ cursor: "pointer", color: on ? "var(--tc-text-sec)" : undefined, display: "flex", gap: "4px" }}>
      {label}{on && <span style={{ color: "var(--tc-blue)" }}>{view.sort.dir === "asc" ? "▲" : "▼"}</span>}
    </div>
  );
}

function TableRow({ a, style, grid, cols, l, sel, onSel, onOpen, tagPill }: {
  a: Asset; style: React.CSSProperties; grid: string; cols: Record<string, boolean>; l: Locale;
  sel: boolean; onSel: () => void; onOpen: () => void; tagPill: (label: string, color: string) => React.ReactNode;
}) {
  const cb = critBucket(a.criticality);
  return (
    <div style={{ ...style, display: "grid", gridTemplateColumns: grid, gap: "10px", alignItems: "center",
      padding: "0 12px", borderBottom: "1px solid var(--tc-border)", cursor: "pointer",
      background: sel ? "rgba(75,142,240,0.08)" : undefined }} onClick={onOpen}>
      <div onClick={e => { e.stopPropagation(); onSel(); }}><Cb on={sel} /></div>
      <div style={{ fontSize: "12.5px", fontWeight: 600, color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</div>
      {cols.ip && <div style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--tc-text-sec)" }}>{a.ip_addresses?.[0] || "—"}</div>}
      {cols.os && <div style={{ fontSize: "11.5px", color: "var(--tc-text-sec)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.os || "—"}</div>}
      {cols.crit && <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11.5px" }}>
        <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: CRIT_DOT[cb] }} />{critLabel(cb, l)}</div>}
      {cols.source && <div style={{ fontSize: "11.5px", color: "var(--tc-text-sec)" }}>{sourceLabel(sourceBucket(a), l)}</div>}
      {cols.tags && <div style={{ display: "flex", gap: "4px", flexWrap: "wrap", overflow: "hidden" }}>
        {(a.user_tags || []).slice(0, 4).map(t => tagPill(t.label, t.color))}</div>}
      <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{formatRelative(a.last_seen, l)}</div>
    </div>
  );
}

function ListRow({ a, style, l, sel, onSel, onOpen, onEdit, onTrash, tagPill }: {
  a: Asset; style: React.CSSProperties; l: Locale; sel: boolean; onSel: () => void; onOpen: () => void;
  onEdit: (a: Asset) => void; onTrash: (a: Asset) => void; tagPill: (label: string, color: string) => React.ReactNode;
}) {
  const cb = critBucket(a.criticality);
  const t = assetType(a.category);
  const Icon = TYPE_ICON[t];
  const sub = [a.ip_addresses?.[0], a.hostname, a.os, sourceLabel(sourceBucket(a), l)].filter(Boolean).join("  ·  ");
  return (
    <div className="tc-listrow" style={{ ...style, display: "flex", alignItems: "center", gap: "12px", padding: "0 12px",
      borderRadius: "10px", cursor: "pointer", background: sel ? "rgba(75,142,240,0.08)" : undefined,
      borderBottom: "1px solid var(--tc-border)" }} onClick={onOpen}>
      <div onClick={e => { e.stopPropagation(); onSel(); }}><Cb on={sel} /></div>
      <span style={{ color: TYPE_COLOR[t], display: "flex" }}><Icon size={16} /></span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
          <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: CRIT_DOT[cb] }} />
          <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)" }}>{a.name}</span>
          {a.role && <span style={{ fontSize: "10px", padding: "2px 7px", borderRadius: "5px", border: "1px solid var(--tc-border)", color: "var(--tc-text-sec)" }}>{a.role}</span>}
          {(a.user_tags || []).map(tg => tagPill(tg.label, tg.color))}
        </div>
        <div className="tc-sub" style={{ fontSize: "11px", color: "var(--tc-text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{sub}</div>
      </div>
      <span onClick={e => { e.stopPropagation(); onEdit(a); }} title={fr(l) ? "Modifier" : "Edit"} style={{ color: "var(--tc-text-muted)", display: "flex", padding: "4px" }}><Pencil size={14} /></span>
      <span onClick={e => { e.stopPropagation(); onTrash(a); }} title={fr(l) ? "Corbeille" : "Trash"} style={{ color: "var(--tc-text-muted)", display: "flex", padding: "4px" }}><Trash2 size={14} /></span>
    </div>
  );
}

function Drawer({ a, l, tagPill, onClose, onEdit, onTrash, onMarkDup }: {
  a: Asset; l: Locale; tagPill: (label: string, color: string) => React.ReactNode;
  onClose: () => void; onEdit: () => void; onTrash: () => void; onMarkDup: () => void;
}) {
  const t = assetType(a.category);
  const cb = critBucket(a.criticality);
  const kv = (k: string, v: string | null | undefined) => (
    <div style={{ display: "flex", justifyContent: "space-between", gap: "12px", padding: "7px 0", borderBottom: "1px solid var(--tc-border)", fontSize: "12px" }}>
      <span style={{ color: "var(--tc-text-muted)" }}>{k}</span>
      <span style={{ color: "var(--tc-text)", textAlign: "right" }}>{v && v !== "Inconnu" ? v : "—"}</span>
    </div>
  );
  const lbl: React.CSSProperties = { fontSize: "10px", letterSpacing: "1.4px", color: "var(--tc-text-muted)", marginBottom: "8px" };
  const policy = (a.user_tags || []).length
    ? (fr(l) ? "Les tags portent une politique (criticité, périmètre de détection, licence) — câblage à venir."
             : "Tags carry a policy (criticality, detection scope, licence) — wiring to come.")
    : (fr(l) ? "Aucune politique. Pose un tag pour appliquer criticité, périmètre de détection et licence en un geste."
             : "No policy. Add a tag to apply criticality, detection scope and licence in one move.");
  const btn: React.CSSProperties = { display: "flex", alignItems: "center", justifyContent: "center", gap: "7px",
    padding: "9px", fontSize: "12px", fontFamily: "inherit", cursor: "pointer", borderRadius: "var(--tc-radius-sm)",
    background: "var(--tc-input)", color: "var(--tc-text)", border: "1px solid var(--tc-border)" };
  return (
    <>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "10px" }}>
        <div>
          <div style={{ fontSize: "16px", fontWeight: 600, color: "var(--tc-text)" }}>{a.name}</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "5px" }}>{typeLabel(t, l)} · {formatRelative(a.last_seen, l)}</div>
        </div>
        <X size={18} style={{ cursor: "pointer", color: "var(--tc-text-muted)" }} onClick={onClose} />
      </div>

      <div style={{ marginTop: "20px" }}>
        <div style={lbl}>TAGS</div>
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
          {(a.user_tags || []).map(tg => tagPill(tg.label, tg.color))}
          <span onClick={onEdit} style={{ fontSize: "11px", color: "var(--tc-text-muted)", border: "1px dashed var(--tc-border)", borderRadius: "20px", padding: "3px 10px", cursor: "pointer" }}>+ tag</span>
        </div>
        <div style={{ marginTop: "10px", fontSize: "11px", color: "var(--tc-text-sec)", background: "rgba(112,48,160,0.07)", border: "1px solid rgba(112,48,160,0.25)", borderRadius: "8px", padding: "9px 11px", lineHeight: 1.5 }}>{policy}</div>
      </div>

      <div style={{ marginTop: "20px" }}>
        <div style={lbl}>{fr(l) ? "IDENTITÉ" : "IDENTITY"}</div>
        {kv("Hostname", a.hostname)}
        {kv(fr(l) ? "Adresse IP" : "IP address", a.ip_addresses?.[0])}
        {kv("Type", typeLabel(t, l))}
        {kv("OS", a.os)}
        {kv("Source", sourceLabel(sourceBucket(a), l))}
      </div>

      <div style={{ marginTop: "20px" }}>
        <div style={lbl}>CLASSIFICATION</div>
        {kv(fr(l) ? "Criticité" : "Criticality", critLabel(cb, l))}
        {kv(fr(l) ? "Rôle" : "Role", a.role)}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "20px" }}>
        <div style={btn} onClick={onEdit}><Pencil size={13} /> {fr(l) ? "Modifier la classification" : "Edit classification"}</div>
        <div style={btn} onClick={onMarkDup}><Copy size={13} /> {fr(l) ? "Marquer comme doublon" : "Mark as duplicate"}</div>
        <div style={btn} onClick={onTrash}><Trash2 size={13} /> {fr(l) ? "Envoyer à la corbeille" : "Send to trash"}</div>
        <a href={`/assets/${a.id}`} style={{ ...btn, textDecoration: "none" }}><ExternalLink size={13} /> {fr(l) ? "Ouvrir la fiche complète" : "Open full record"}</a>
      </div>
    </>
  );
}

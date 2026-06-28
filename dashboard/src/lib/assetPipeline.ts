// Pure filter / sort / group pipeline for the assets inventory.
//
// Kept free of React and of any network call so it can be unit-tested and,
// if the 10k-host volume ever outgrows client-side memory, lifted to the
// server with the same semantics. The inventory page is the only caller.
import type { Asset } from "@/lib/asset-shared";

export type AssetType = "srv" | "pc" | "net" | "unk";
export type SourceBucket = "agent" | "syslog" | "passif";
export type CritBucket = "haut" | "moyen" | "bas";
export type SortKey = "name" | "ip" | "os" | "crit" | "seen";
export type SortDir = "asc" | "desc";
export type GroupKey = "none" | "os" | "tag" | "subnet" | "type" | "source";

export interface Filters {
  source: SourceBucket[];
  crit: CritBucket[];
  tag: string[];
  os: string[];
}

export const EMPTY_FILTERS: Filters = { source: [], crit: [], tag: [], os: [] };

/** Map the backend `category` onto the four inventory type buckets. */
export function assetType(category: string | null | undefined): AssetType {
  switch ((category || "").toLowerCase()) {
    case "server":
      return "srv";
    case "workstation":
    case "laptop":
    case "mobile":
      return "pc";
    case "network":
    case "printer":
      return "net";
    default:
      return "unk";
  }
}

// Source classification — aligned with billing.rs DECLARED/PERSISTENT sources.
const AGENT_SOURCES = new Set([
  "osquery", "velociraptor", "wazuh", "wazuh-agent", "wazuh_agent", "ad",
  "active_directory", "azure_ad", "entra_id", "m365", "intune", "manual", "glpi",
]);
const SYSLOG_SOURCES = new Set(["syslog", "alert-auto", "rssi", "react_l1", "fluent-bit", "fluentbit"]);

/** Classify an asset into one of the three Source facet buckets. */
export function sourceBucket(a: Asset): SourceBucket {
  const s = (a.source || "").toLowerCase();
  if (AGENT_SOURCES.has(s)) return "agent";
  if (SYSLOG_SOURCES.has(s)) return "syslog";
  return "passif"; // nmap, dhcp, pfsense, opnsense, firewall, …
}

/** Fold the 4-level criticality onto the 3 facet/dot buckets. */
export function critBucket(criticality: string | null | undefined): CritBucket {
  switch ((criticality || "").toLowerCase()) {
    case "critical":
    case "high":
      return "haut";
    case "medium":
      return "moyen";
    default:
      return "bas";
  }
}

/** /24 subnet label of the asset's first IP (or "Sans IP"). */
export function subnet24(a: Asset): string {
  const ip = a.ip_addresses?.[0];
  if (!ip) return "—";
  const p = ip.split(".");
  return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : "—";
}

/** Operator tag labels for an asset (entity tags only). */
export function userTagLabels(a: Asset): string[] {
  return (a.user_tags || []).map((t) => t.label);
}

/** Does an asset survive the active type filter + facets + free-text search? */
export function passes(a: Asset, type: AssetType | "all", filters: Filters, search: string): boolean {
  if (type !== "all" && assetType(a.category) !== type) return false;
  if (filters.source.length && !filters.source.includes(sourceBucket(a))) return false;
  if (filters.crit.length && !filters.crit.includes(critBucket(a.criticality))) return false;
  if (filters.os.length && !filters.os.includes(a.os || "")) return false;
  if (filters.tag.length) {
    const labels = userTagLabels(a);
    if (!filters.tag.some((t) => labels.includes(t))) return false;
  }
  if (search) {
    const q = search.toLowerCase();
    const hay = [a.name, ...(a.ip_addresses || []), a.hostname, a.os, a.role, ...userTagLabels(a)]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

const CRIT_ORDER: Record<CritBucket, number> = { haut: 0, moyen: 1, bas: 2 };

/** Stable sort by the chosen key + direction (name is the tie-breaker). */
export function sortAssets(list: Asset[], key: SortKey, dir: SortDir): Asset[] {
  const mul = dir === "desc" ? -1 : 1;
  const byName = (x: Asset, y: Asset) => x.name.localeCompare(y.name);
  return list.slice().sort((x, y) => {
    let c = 0;
    switch (key) {
      case "ip":
        c = (x.ip_addresses?.[0] || "~").localeCompare(y.ip_addresses?.[0] || "~");
        break;
      case "os":
        c = (x.os || "~").localeCompare(y.os || "~");
        break;
      case "crit":
        c = CRIT_ORDER[critBucket(x.criticality)] - CRIT_ORDER[critBucket(y.criticality)];
        break;
      case "seen":
        c = (x.last_seen || "").localeCompare(y.last_seen || "");
        break;
      default:
        c = byName(x, y);
    }
    return (c || byName(x, y)) * mul;
  });
}

/** Group a (already sorted) list. Returns [groupLabel, rows][]; "" = ungrouped. */
export function groupAssets(
  list: Asset[],
  group: GroupKey,
  typeLabel: (t: AssetType) => string,
  sourceLabel: (s: SourceBucket) => string,
  noTagLabel: string,
): Array<[string, Asset[]]> {
  if (group === "none") return [["", list]];
  const keyOf = (a: Asset): string | string[] => {
    switch (group) {
      case "os":
        return a.os || "—";
      case "type":
        return typeLabel(assetType(a.category));
      case "source":
        return sourceLabel(sourceBucket(a));
      case "subnet":
        return subnet24(a);
      case "tag": {
        const labels = userTagLabels(a);
        return labels.length ? labels : [noTagLabel];
      }
      default:
        return "—";
    }
  };
  const map = new Map<string, Asset[]>();
  for (const a of list) {
    const k = keyOf(a);
    for (const kk of Array.isArray(k) ? k : [k]) {
      const arr = map.get(kk) || [];
      arr.push(a);
      map.set(kk, arr);
    }
  }
  return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
}

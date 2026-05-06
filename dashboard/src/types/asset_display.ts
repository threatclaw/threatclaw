// Asset display helpers for the dashboard.
//
// Backend incidents endpoints (`GET /api/tc/incidents`,
// `GET /api/tc/incidents/:id`, `GET /api/tc/incidents/:id/full`) expose:
//   * `asset`            — canonical id (e.g. `asset-bc2411e4af27`)
//   * `asset_name`       — friendly name (e.g. `debian`)        [Phase 9f]
//   * `asset_hostname`   — DNS / NetBIOS hostname               [Phase 9f]
//   * `asset_ips`        — array of IPs (port / CIDR stripped)  [Phase 9f]
//
// Old payloads — incidents created before Phase 9f, or assets removed from
// inventory — only carry `asset`. Helpers below render gracefully in either
// case.

export interface AssetDisplayFields {
  asset?: string | null;
  asset_name?: string | null;
  asset_hostname?: string | null;
  asset_ips?: string[] | null;
}

/**
 * Render the asset for the operator. Examples:
 *
 *   {asset: "asset-bc...", asset_name: "debian", asset_ips: ["10.77.0.136"]}
 *     → "debian (10.77.0.136)"
 *
 *   {asset: "asset-xyz", asset_name: "srv-01"}
 *     → "srv-01"
 *
 *   {asset: "10.77.0.136"}            (legacy, no hydration)
 *     → "10.77.0.136"
 *
 *   {asset: "asset-bc..."}            (asset removed from inventory)
 *     → "asset-bc..." (last-resort fallback — operator still has a handle)
 */
export function displayAsset(inc: AssetDisplayFields): string {
  const name = inc.asset_name?.trim() || inc.asset_hostname?.trim() || "";
  const ips = (inc.asset_ips ?? []).filter((ip) => !!ip);
  if (name && ips.length > 0) return `${name} (${ips[0]})`;
  if (name) return name;
  if (ips.length > 0) return ips[0];
  return inc.asset?.trim() || "—";
}

/**
 * Short variant for tight horizontal space (table columns, badges). Returns
 * the friendly name when available and falls back to the IP, then to the raw
 * asset id. Skips the parenthesised IP suffix to save room.
 */
export function displayAssetShort(inc: AssetDisplayFields): string {
  if (inc.asset_name?.trim()) return inc.asset_name.trim();
  if (inc.asset_hostname?.trim()) return inc.asset_hostname.trim();
  const ips = (inc.asset_ips ?? []).filter((ip) => !!ip);
  if (ips.length > 0) return ips[0];
  return inc.asset?.trim() || "—";
}

/**
 * For tooltips / hover details. Lists every identifier we know about the
 * asset, separated by spaces.
 */
export function displayAssetVerbose(inc: AssetDisplayFields): string {
  const parts: string[] = [];
  if (inc.asset_name) parts.push(inc.asset_name);
  if (inc.asset_hostname && inc.asset_hostname !== inc.asset_name) {
    parts.push(`hostname=${inc.asset_hostname}`);
  }
  const ips = (inc.asset_ips ?? []).filter((ip) => !!ip);
  if (ips.length > 0) parts.push(`ips=${ips.join(",")}`);
  if (inc.asset) parts.push(`id=${inc.asset}`);
  return parts.join(" ") || "—";
}

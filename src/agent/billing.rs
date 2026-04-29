//! Phase A.2 of the 2026-04-28 pricing pivot — billable asset accounting.
//!
//! The new pricing model bills by the number of distinct, internal,
//! actively-monitored devices ThreatClaw is keeping eyes on. Not by
//! HITL action (Phase A.1 freed those), not by feature (every tier
//! gets every feature), just by parc size.
//!
//! Tier limits (see `BillingTier`):
//!
//!   Free       0-50       0 €
//!   Starter    51-200     99 €/mo  / 990 €/yr
//!   Pro        201-600    249 €/mo / 2 490 €/yr
//!   Business   601-1500   599 €/mo / 5 990 €/yr
//!   Enterprise 1500+      sur devis (also required for any MSSP setup)
//!
//! What counts as billable (the SQL filter applied below — V67 model):
//!
//!   - row exists in `assets` (ie went through the resolution pipeline)
//!   - `demo` is false (setup wizard demo data is excluded)
//!   - `dedup_confidence` is not 'uncertain' (a half-resolved DHCP
//!     ghost shouldn't tip a customer over their tier)
//!   - `category` is one of the device-types we actually monitor
//!     (server / workstation / mobile / network / printer / iot / ot)
//!   - `last_seen` is within the last 30 days (asset still in the parc)
//!   - **persistence signal** — one of:
//!       * `inventory_status = 'declared'` (AD / osquery / Velociraptor /
//!         M365 / Intune — explicit enrollment by the customer)
//!       * `inventory_status = 'observed_persistent'` (firewall / switch /
//!         AP connector reports the asset as a managed entity)
//!       * `inventory_status = 'observed_transient'` AND
//!         `distinct_days_seen_30d >= 3` (passive sighting that came
//!         back enough times to look like a real client device, not a
//!         one-off Wi-Fi guest)
//!
//! V66 strict filter is the legacy "had a finding in the last 30d"
//! definition. It returned 0 billable on a fresh install with 19 assets
//! in inventory because none had findings yet — wrong intuition for a
//! pricing tier called "monitored assets". V67 promotes anything we're
//! actively monitoring (declared by an agent / connector, or seen
//! persistently) to billable from day 0.
//!
//! Two long-running concerns live here:
//!
//!   `count_billable_assets` — single query the dashboard widget and the
//!     license gate both call.
//!   `reclassify_assets_job` — periodic sweep that flips
//!     monitored → inactive after 30 days of silence so the count
//!     decays automatically when devices fall out of the parc.
//!
//! The actual UPDATE from new findings is handled by the V66 trigger,
//! not by this module. We just consult and reclassify.

use std::sync::Arc;

use serde::Serialize;
use tracing::{info, warn};

use crate::db::Database;

/// What the count-billable endpoint returns for the UI widget. Rich
/// enough to render the gauge + the "what doesn't count" disclosure
/// without a second round-trip.
#[derive(Debug, Clone, Serialize)]
pub struct BillableCount {
    /// Number of monitored, billable assets at this instant.
    pub billable: i64,
    /// Total assets in the table (any status, demo included). Useful
    /// to surface "you have 47 billable but TC has seen 312 IPs in
    /// total — here's why those don't count".
    pub total: i64,
    /// Breakdown of billable assets by category.
    pub by_category: Vec<(String, i64)>,
    /// Number of assets in `discovered` state (seen but no event yet).
    pub discovered: i64,
    /// Number of assets aged out (`inactive`).
    pub inactive: i64,
    /// Number of assets in `uncertain` dedup state — flagged for the
    /// operator to merge / fix the underlying ID source.
    pub uncertain: i64,
    /// Demo/wizard rows currently in the table.
    pub demo: i64,
}

/// Categories that count toward the tier limit. Aligned exactly with
/// what the catalog seeds in `migrations/V24__assets_management.sql`
/// — `fingerprint::guess_category` only ever emits these values, so
/// any divergence here = silent under-count.
///
/// What's billable (real devices ThreatClaw monitors actively):
///   - server, workstation, mobile (smartphones/tablets with MDM/agent)
///   - network (firewall / switch / router / wifi-ap — `subcategory`
///     refines but the parent category is what we count)
///   - printer, iot, ot
///
/// What's NOT billable (intentionally excluded):
///   - `website` — an externally-monitored URL/SaaS is not a device
///     in the ThreatClaw "asset" sense (it has no agent, no LATERAL
///     reachability, no findings table contribution). If a customer
///     wants to count their websites, that's a separate Web Security
///     SKU later.
///   - `cloud` — covers VMs / containers / SaaS accounts / storage
///     buckets. Ambiguous billing surface (one Kubernetes cluster
///     with 200 ephemeral containers must not = 200 assets). Treat
///     as Enterprise contract for now.
///   - `unknown` — auto-discovered IPs on internal subnets that
///     ThreatClaw saw once but has no real source for. Promoting
///     these to billable would let a customer accidentally rack up
///     50+ entries from a single `nmap -sP`.
const BILLABLE_CATEGORIES: &[&str] = &[
    "server",
    "workstation",
    "mobile",
    "network",
    "printer",
    "iot",
    "ot",
];

/// Categories that are NEVER billable, even when persistence is high.
/// They have their own SKU surface (or are intentionally ephemeral).
/// A declared / observed_persistent asset that lands here is excluded
/// from the count.
const EXCLUDED_CATEGORIES: &[&str] = &[
    "website",   // separate Web Security SKU
    "cloud",     // separate Cloud Posture SKU
    "container", // ephemeral, count the cluster/host instead
    "pod",
    "lambda",
    "function",
];

/// Sources that count as a "declared" enrollment — the customer
/// explicitly told ThreatClaw about this asset (agent installed,
/// directory entry, MDM-managed). High-confidence persistence.
const DECLARED_SOURCES: &[&str] = &[
    "active_directory",
    "ad",
    "azure_ad",
    "entra_id",
    "m365",
    "osquery",
    "velociraptor",
    "wazuh-agent",
    "wazuh_agent",
    "intune",
    "manual", // operator added the row by hand
];

/// Sources that count as "observed_persistent" — a network connector
/// that owns this asset as a managed entity (firewall, switch, AP).
/// Medium-confidence persistence: the connector reports it on every
/// sync, but the asset has no agent of its own.
const PERSISTENT_SOURCES: &[&str] = &[
    "pfsense",
    "opnsense",
    "fortinet",
    "fortigate",
    "mikrotik",
    "unifi",
    "cisco",
    "aruba",
    "proxmox",
    "freebox",
];

/// Map a source string (the `assets.source` column) to the
/// `inventory_status` it should imply. Anything unknown falls into
/// `observed_transient` — the safe default that requires the
/// 3-distinct-days threshold to count.
pub fn inventory_status_for(source: &str) -> &'static str {
    let s = source.to_lowercase();
    if DECLARED_SOURCES.iter().any(|d| *d == s) {
        "declared"
    } else if PERSISTENT_SOURCES.iter().any(|p| *p == s) {
        "observed_persistent"
    } else {
        "observed_transient"
    }
}

/// SQL filter shared by the count, the list, and the reclassify job.
/// Centralized so we can't accidentally diverge across callers.
///
/// V67 model — see the module-level doc for the rationale. The
/// distinct_days_seen_30d threshold for transient assets is exposed
/// as a constant so the test, the reclassify job and the SQL all
/// agree.
const TRANSIENT_DAYS_THRESHOLD: i32 = 3;

fn billable_filter_sql() -> String {
    // Category logic by persistence bucket:
    //   declared / observed_persistent → category may be 'unknown' (we
    //     trust the persistence signal). Still exclude the SKU-isolated
    //     categories (website / cloud / container / pod / lambda /
    //     function) which have their own product surface.
    //   observed_transient → category MUST be in BILLABLE_CATEGORIES
    //     ($1). A transient 'unknown' is exactly the "random nmap IP"
    //     case we're trying NOT to count.
    //
    // Why category may be 'unknown' for declared assets: the AD /
    // osquery / connector pipelines often land an asset before the
    // fingerprint::guess_category classifier has had a chance to look
    // at it. The asset is still a real device the customer is
    // monitoring. We bill it.
    let excluded: String = EXCLUDED_CATEGORIES
        .iter()
        .map(|c| format!("'{c}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "demo = false \
         AND excluded = false \
         AND status = 'active' \
         AND dedup_confidence != 'uncertain' \
         AND last_seen > NOW() - INTERVAL '30 days' \
         AND ( \
             ( \
                 inventory_status IN ('declared','observed_persistent') \
                 AND category NOT IN ({excluded_cats}) \
             ) \
             OR ( \
                 inventory_status = 'observed_transient' \
                 AND distinct_days_seen_30d >= {threshold} \
                 AND category = ANY($1) \
             ) \
         )",
        excluded_cats = excluded,
        threshold = TRANSIENT_DAYS_THRESHOLD,
    )
}

/// Single hit query for the dashboard widget + license gate.
pub async fn count_billable_assets(store: &Arc<dyn Database>) -> Result<BillableCount, String> {
    let conn_owned = store.clone();
    let categories: Vec<String> = BILLABLE_CATEGORIES.iter().map(|s| s.to_string()).collect();

    // We ask the store for raw rows because the existing
    // `count_assets_filtered` is too coarse (no category-array, no
    // billable_status). This hits a single connection and aggregates in
    // one round-trip.
    let breakdown = conn_owned
        .billable_breakdown(&categories)
        .await
        .map_err(|e| format!("billable breakdown query failed: {e}"))?;
    Ok(breakdown)
}

/// Periodic sweep — flips `monitored` to `inactive` for assets that
/// haven't seen an event in 30 days, AND lifts expired manual
/// exclusions (V68). Idempotent and bounded, safe on every tick.
///
/// Returns the total number of rows changed across both passes.
pub async fn reclassify_assets_job(store: &Arc<dyn Database>) -> Result<u64, String> {
    let inactive_n = store
        .reclassify_inactive_assets(30)
        .await
        .map_err(|e| format!("reclassify failed: {e}"))?;
    if inactive_n > 0 {
        info!(
            "BILLING: reclassified {} assets monitored → inactive (no event in 30d)",
            inactive_n
        );
    }
    let unexcluded_n = store
        .expire_asset_exclusions()
        .await
        .map_err(|e| format!("expire exclusions failed: {e}"))?;
    if unexcluded_n > 0 {
        info!(
            "BILLING: lifted {} expired exclusions (90-day window passed) — assets back to active monitoring",
            unexcluded_n
        );
    }
    Ok(inactive_n + unexcluded_n)
}

/// Spawn the daily reclassification cron. Caller is responsible for
/// only spawning this once per process (typically from `boot_services`).
pub fn spawn_reclassify_scheduler(store: Arc<dyn Database>) {
    tokio::spawn(async move {
        // Stagger 5 min after boot so we don't fight the V66 trigger
        // backfill or the path-risk batch for connection slots.
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(86_400));
        info!("BILLING SCHEDULER: started (every 24h)");
        loop {
            ticker.tick().await;
            let store_arc = Arc::clone(&store);
            if let Err(e) = reclassify_assets_job(&store_arc).await {
                warn!("BILLING SCHEDULER: reclassify failed: {}", e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billable_categories_exclude_ambiguous_and_meta_categories() {
        // Tripwire: these are real categories seeded by V24 OR meta
        // placeholders that may end up in the `assets` table from edge
        // code paths. Adding any of them to BILLABLE_CATEGORIES would
        // silently inflate the count — block at compile-test time.
        for excluded in &[
            // Real V24 categories we deliberately don't bill on:
            "website",
            "cloud",
            "unknown",
            // Meta placeholders that should never reach `assets` but
            // we guard against regressions:
            "ip",
            "threat_actor",
            "cve",
            "user",
            // Ephemeral compute categories — a 200-pod cluster must
            // never become 200 assets. The cluster (or the host) is the
            // billable entity, the pods/containers/lambdas are not.
            // See pricing pivot decision 2026-04-29 §3.
            "container",
            "pod",
            "lambda",
            "function",
        ] {
            assert!(
                !BILLABLE_CATEGORIES.contains(excluded),
                "category '{}' must not be in BILLABLE_CATEGORIES",
                excluded
            );
        }
    }

    #[test]
    fn billable_categories_cover_every_real_device_seeded_by_v24() {
        // The 7 V24 seeded categories that DO represent monitored
        // physical/logical devices — must all be billable.
        for required in &[
            "server",
            "workstation",
            "mobile",
            "network",
            "printer",
            "iot",
            "ot",
        ] {
            assert!(
                BILLABLE_CATEGORIES.contains(required),
                "category '{}' must be in BILLABLE_CATEGORIES",
                required
            );
        }
    }

    #[test]
    fn billable_categories_match_v24_exactly() {
        // Hard tripwire: BILLABLE_CATEGORIES must equal the union of
        // (real-device V24 categories) — no extras, no missing. If
        // V24 grows or shrinks the catalog, this test forces a
        // conscious update here.
        let mut got: Vec<&str> = BILLABLE_CATEGORIES.iter().copied().collect();
        got.sort();
        let mut want = vec![
            "iot",
            "mobile",
            "network",
            "ot",
            "printer",
            "server",
            "workstation",
        ];
        want.sort();
        assert_eq!(got, want, "BILLABLE_CATEGORIES drifted from V24 catalog");
    }

    #[test]
    fn filter_sql_uses_v67_persistence_signals() {
        // V67 — the filter must check inventory_status against the
        // three billable buckets. Declared / persistent are accepted
        // even with category 'unknown' (we trust the source); only
        // transient enforces the strict BILLABLE_CATEGORIES list.
        let sql = billable_filter_sql();
        assert!(sql.contains("demo = false"));
        assert!(sql.contains("excluded = false"));
        assert!(sql.contains("dedup_confidence"));
        assert!(sql.contains("inventory_status IN ('declared','observed_persistent')"));
        assert!(sql.contains("inventory_status = 'observed_transient'"));
        assert!(sql.contains("distinct_days_seen_30d"));
        assert!(sql.contains("last_seen > NOW()"));
        // Excluded categories appear in the NOT IN clause so a 'cloud'
        // declared-by-connector entity doesn't rack up the count.
        assert!(sql.contains("'website'"));
        assert!(sql.contains("'cloud'"));
        assert!(sql.contains("'container'"));
    }

    #[test]
    fn transient_threshold_is_three_days() {
        // The threshold lives at three places (filter SQL, doc, tests).
        // Lock it here so a refactor that drops one of the places fails
        // visibly.
        assert_eq!(TRANSIENT_DAYS_THRESHOLD, 3);
        let sql = billable_filter_sql();
        assert!(sql.contains("distinct_days_seen_30d >= 3"));
    }

    #[test]
    fn inventory_status_for_known_sources() {
        // Declared sources — agent or identity provider, immediate billable.
        assert_eq!(inventory_status_for("active_directory"), "declared");
        assert_eq!(inventory_status_for("osquery"), "declared");
        assert_eq!(inventory_status_for("velociraptor"), "declared");
        assert_eq!(inventory_status_for("m365"), "declared");
        assert_eq!(inventory_status_for("intune"), "declared");
        assert_eq!(inventory_status_for("manual"), "declared");

        // Network connectors that own the asset.
        assert_eq!(inventory_status_for("pfsense"), "observed_persistent");
        assert_eq!(inventory_status_for("opnsense"), "observed_persistent");
        assert_eq!(inventory_status_for("fortinet"), "observed_persistent");
        assert_eq!(inventory_status_for("unifi"), "observed_persistent");

        // Passive / unknown — transient (must reach 3 distinct days).
        assert_eq!(inventory_status_for("nmap"), "observed_transient");
        assert_eq!(inventory_status_for("dhcp"), "observed_transient");
        assert_eq!(inventory_status_for("alert-auto"), "observed_transient");
        assert_eq!(
            inventory_status_for("brand-new-source"),
            "observed_transient"
        );

        // Case insensitive.
        assert_eq!(inventory_status_for("OSquery"), "declared");
        assert_eq!(inventory_status_for("PFSense"), "observed_persistent");
    }
}

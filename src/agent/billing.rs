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
//! What counts as billable (the SQL filter applied below):
//!
//!   - row exists in `assets` (ie went through the resolution pipeline)
//!   - `demo` is false (setup wizard demo data is excluded)
//!   - `dedup_confidence` is not 'uncertain' (a half-resolved DHCP
//!     ghost shouldn't tip a customer over their tier)
//!   - `category` is one of the device-types we actually monitor
//!     (server / workstation / network_device / iot / nas) — excludes
//!     bare IPs and unknown blobs
//!   - `last_event_at` is within the last 30 days — the asset has
//!     actually generated something we acted on
//!   - `billable_status` is 'monitored'
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

/// SQL filter shared by the count, the list, and the reclassify job.
/// Centralized so we can't accidentally diverge across callers.
fn billable_filter_sql() -> &'static str {
    "demo = false \
     AND status = 'active' \
     AND dedup_confidence != 'uncertain' \
     AND category = ANY($1) \
     AND last_event_at > NOW() - INTERVAL '30 days' \
     AND billable_status = 'monitored'"
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
/// haven't seen an event in 30 days. The V66 trigger handles the other
/// direction (any new finding promotes back to monitored). This pass
/// is idempotent and bounded so it's safe to run on every tick.
///
/// Returns the number of rows that changed state.
pub async fn reclassify_assets_job(store: &Arc<dyn Database>) -> Result<u64, String> {
    let n = store
        .reclassify_inactive_assets(30)
        .await
        .map_err(|e| format!("reclassify failed: {e}"))?;
    if n > 0 {
        info!(
            "BILLING: reclassified {} assets monitored → inactive (no event in 30d)",
            n
        );
    }
    Ok(n)
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
            "container",
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
    fn filter_sql_uses_indexed_columns() {
        // The V66 index is on (billable_status, last_event_at) WHERE
        // demo = false. The filter string must reference those columns
        // verbatim or the index won't be picked.
        let sql = billable_filter_sql();
        assert!(sql.contains("billable_status"));
        assert!(sql.contains("last_event_at"));
        assert!(sql.contains("demo = false"));
    }
}

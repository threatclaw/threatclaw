//! Helpers around the `scan_queue` table.
//!
//! These are convenience wrappers over `ThreatClawStore::enqueue_scan` —
//! they pin the scan_type string and set a sensible default TTL for each
//! scan family. Callers in hooks (assets::merge, findings::create, ...)
//! and in dashboard handlers reach for these instead of constructing
//! `NewScanRequest` by hand, so we have one place to tune intervals.
//!
//! Convention for `requested_by`:
//!   - `auto:asset_merge`           — passive enrichment hook
//!   - `auto:finding_container`     — passive trivy hook
//!   - `manual:rssi:<userid>`       — dashboard "Lancer maintenant"
//!   - `schedule:<cron_id>`         — recurring scan from the scheduler

use crate::db::Database;
use crate::db::threatclaw_store::NewScanRequest;
use crate::error::DatabaseError;

pub const NMAP_FINGERPRINT: &str = "nmap_fingerprint";
pub const TRIVY_IMAGE: &str = "trivy_image";

/// 1 hour — re-fingerprint an asset at most once per hour automatically.
pub const NMAP_DEFAULT_TTL: i32 = 3600;
/// 24 hours — re-scan an image at most once per day automatically.
pub const TRIVY_DEFAULT_TTL: i32 = 86400;

/// Enqueue an Nmap fingerprint of a single host. Returns the queue id,
/// or `None` if a recent scan already exists (TTL dedup).
pub async fn enqueue_nmap_fingerprint(
    store: &dyn Database,
    target_ip: &str,
    asset_id: Option<String>,
    requested_by: &str,
    ttl_seconds: Option<i32>,
) -> Result<Option<i64>, DatabaseError> {
    let req = NewScanRequest {
        target: target_ip.to_string(),
        scan_type: NMAP_FINGERPRINT.into(),
        asset_id,
        requested_by: requested_by.to_string(),
        ttl_seconds: Some(ttl_seconds.unwrap_or(NMAP_DEFAULT_TTL)),
    };
    store.enqueue_scan(&req).await
}

/// Enqueue a Trivy CVE scan of a Docker image. Image format is the
/// usual `name:tag` or `registry/name:tag`.
pub async fn enqueue_trivy_image(
    store: &dyn Database,
    image: &str,
    asset_id: Option<String>,
    requested_by: &str,
    ttl_seconds: Option<i32>,
) -> Result<Option<i64>, DatabaseError> {
    let req = NewScanRequest {
        target: image.to_string(),
        scan_type: TRIVY_IMAGE.into(),
        asset_id,
        requested_by: requested_by.to_string(),
        ttl_seconds: Some(ttl_seconds.unwrap_or(TRIVY_DEFAULT_TTL)),
    };
    store.enqueue_scan(&req).await
}

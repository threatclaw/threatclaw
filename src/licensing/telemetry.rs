//! Anonymous install telemetry.
//!
//! Every ThreatClaw install (free OR paid) pings the license server
//! every 7 days with a minimal, anonymous payload:
//!
//!   - `install_id` — the random UUID generated on first boot. Not
//!     user-identifying.
//!   - `version` — agent semver (`env!("CARGO_PKG_VERSION")`).
//!   - `tier` — one of `free / starter / pro / business / trial / ...`.
//!   - `asset_count` — exact number; the server buckets it before
//!     storage so we never persist exact fleet sizes.
//!
//! No email, no IP, no hostname, no path on disk. The IP is read by
//! Cloudflare for geo-resolution (CF-IPCountry) and discarded after
//! the country code is computed.
//!
//! Opt-out: setting the environment variable `TC_TELEMETRY_DISABLED=1`
//! at agent startup skips the spawn entirely. The spawn function logs
//! that it has done so.
//!
//! See `docs/telemetry.md` for the public-facing description.
//!
//! # Failure mode
//!
//! Telemetry is best-effort. Network errors, server errors, parse
//! errors are all swallowed silently — we never bubble up to the
//! caller, and we never retry. The next 7-day tick is the retry.

use std::sync::Arc;
use std::time::Duration;

use super::api_client::{AnonymousHeartbeatRequest, LicenseClient};
use super::manager::LicenseManager;

/// Cadence of the anonymous ping. Same as the licensed heartbeat (7d)
/// to keep wire-pattern noise predictable.
const TELEMETRY_INTERVAL: Duration = Duration::from_secs(7 * 86_400);

/// Initial delay so a stampede of restarts (e.g. coordinated upgrade)
/// doesn't all hit the worker at once. A bit longer than the licensed
/// heartbeat boot delay, so the first activate / heartbeat lands first.
const TELEMETRY_BOOT_DELAY: Duration = Duration::from_secs(180);

/// Returns true if telemetry is opted out via env var.
pub fn is_disabled() -> bool {
    matches!(
        std::env::var("TC_TELEMETRY_DISABLED")
            .unwrap_or_default()
            .as_str(),
        "1" | "true" | "TRUE" | "yes" | "YES"
    )
}

/// Spawn the background telemetry task. Caller MUST hold the returned
/// `JoinHandle` (or drop it) — typically the process supervisor owns it
/// for the lifetime of the agent.
///
/// `asset_count_fn` is invoked every tick to read the current billable
/// asset count from the running database. Returning 0 is fine (the
/// server buckets `0-50` correctly).
pub fn spawn_telemetry<F>(
    license_manager: Arc<LicenseManager>,
    client: LicenseClient,
    asset_count_fn: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> futures::future::BoxFuture<'static, u32> + Send + Sync + 'static,
{
    if is_disabled() {
        tracing::info!("telemetry: disabled by TC_TELEMETRY_DISABLED");
        // Spawn a no-op task to keep the return type consistent.
        return tokio::spawn(async {});
    }

    tokio::spawn(async move {
        tokio::time::sleep(TELEMETRY_BOOT_DELAY).await;

        loop {
            let install_id = license_manager.install_id().to_string();
            let status = license_manager.status().await;
            let tier = pick_tier(&status);
            let asset_count = asset_count_fn().await;
            let version = env!("CARGO_PKG_VERSION");

            let req = AnonymousHeartbeatRequest {
                install_id: &install_id,
                version,
                tier: &tier,
                asset_count,
            };
            match client.anonymous_heartbeat(&req).await {
                Ok(()) => {
                    tracing::debug!(install_id = %install_id, tier = %tier, "telemetry ping ok");
                }
                Err(e) => {
                    // Best-effort. Log and move on — next tick is the retry.
                    tracing::debug!(error = ?e, "telemetry ping failed (best-effort, ignored)");
                }
            }

            tokio::time::sleep(TELEMETRY_INTERVAL).await;
        }
    })
}

/// Pick the tier label for the ping. If any active license exists, use
/// the highest one (Business > Pro > Starter > Trial). Otherwise free.
fn pick_tier(status: &super::manager::LicenseStatus) -> String {
    use super::cert::LicenseTier;

    let mut best: Option<LicenseTier> = None;
    for license in &status.licenses {
        if !license.active {
            continue;
        }
        let cur = license.tier;
        match best {
            None => best = Some(cur),
            Some(b) => {
                if tier_rank(cur) > tier_rank(b) {
                    best = Some(cur);
                }
            }
        }
    }
    match best {
        Some(t) => format!("{:?}", t).to_lowercase(),
        None => "free".to_string(),
    }
}

fn tier_rank(t: super::cert::LicenseTier) -> u8 {
    use super::cert::LicenseTier::*;
    match t {
        Trial => 1,
        Individual | ActionPack | Starter => 2,
        Pro => 3,
        Business => 4,
        Msp | Enterprise => 5,
    }
}

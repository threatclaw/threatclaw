//! Scan schedule tick — turns recurring plans into queued jobs.
//!
//! Runs every 60 s. Each tick:
//!   1. Pull every row in `scan_schedules` with `enabled=true AND next_run_at <= now()`.
//!   2. For each due row, enqueue a `scan_queue` job (ttl_seconds=0 so manual-style
//!      dedup never fires for schedules — if the operator wanted a daily scan, they
//!      get a daily scan, period).
//!   3. Compute the next slot and write it back via `bump_scan_schedule`.
//!
//! Frequency semantics (kept deliberately simple — no full cron):
//!   - hourly:  fires at every `:minute` of the hour
//!   - daily:   fires once a day at `hour:minute`
//!   - weekly:  fires once a week on `day_of_week` (0=Mon..6=Sun) at `hour:minute`
//!   - monthly: fires once a month on `day_of_month` (1..28) at `hour:minute`

use crate::db::Database;
use crate::db::threatclaw_store::{NewScanRequest, ScanSchedule};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, TimeZone, Timelike, Utc, Weekday};
use std::sync::Arc;

/// Spawn the schedule tick. Call once at startup, after the worker pool.
pub fn spawn_schedule_tick(store: Arc<dyn Database>) {
    tokio::spawn(async move {
        // Stagger first tick by 10 s so we don't slam the DB right when
        // the container boots.
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        tracing::info!("SCAN SCHEDULE: tick started (every 60 s)");
        loop {
            ticker.tick().await;
            if let Err(e) = run_once(store.as_ref()).await {
                tracing::warn!("SCAN SCHEDULE: tick error: {}", e);
            }
        }
    });
}

async fn run_once(store: &dyn Database) -> Result<(), String> {
    let due = store
        .fetch_due_scan_schedules()
        .await
        .map_err(|e| format!("fetch_due failed: {e}"))?;
    if due.is_empty() {
        return Ok(());
    }
    tracing::info!("SCAN SCHEDULE: {} schedule(s) due", due.len());
    for sched in due {
        let next = compute_next_run(&sched, Utc::now());
        let req = NewScanRequest {
            target: sched.target.clone(),
            scan_type: sched.scan_type.clone(),
            asset_id: None,
            requested_by: format!("schedule:{}", sched.id),
            ttl_seconds: Some(0), // schedules always run, no dedup
        };
        if let Err(e) = store.enqueue_scan(&req).await {
            tracing::warn!(
                "SCAN SCHEDULE: failed to enqueue from schedule #{}: {}",
                sched.id,
                e
            );
            continue;
        }
        if let Err(e) = store.bump_scan_schedule(sched.id, next).await {
            tracing::warn!(
                "SCAN SCHEDULE: failed to bump schedule #{}: {}",
                sched.id,
                e
            );
        } else {
            tracing::info!(
                "SCAN SCHEDULE: enqueued from schedule #{} ({}/{}); next = {}",
                sched.id,
                sched.scan_type,
                sched.target,
                next.to_rfc3339()
            );
        }
    }
    Ok(())
}

/// Compute the next absolute UTC instant the schedule should fire,
/// strictly after `now`. Public so the API handler can compute the
/// initial `next_run_at` when an operator creates a schedule.
pub fn compute_next_run(sched: &ScanSchedule, now: DateTime<Utc>) -> DateTime<Utc> {
    let minute = sched.minute.clamp(0, 59) as u32;
    let hour = sched.hour.unwrap_or(0).clamp(0, 23) as u32;
    match sched.frequency.as_str() {
        "hourly" => {
            let candidate = now
                .with_minute(minute)
                .and_then(|t| t.with_second(0))
                .and_then(|t| t.with_nanosecond(0))
                .unwrap_or(now);
            if candidate > now {
                candidate
            } else {
                candidate + Duration::hours(1)
            }
        }
        "daily" => {
            let candidate = now
                .with_hour(hour)
                .and_then(|t| t.with_minute(minute))
                .and_then(|t| t.with_second(0))
                .and_then(|t| t.with_nanosecond(0))
                .unwrap_or(now);
            if candidate > now {
                candidate
            } else {
                candidate + Duration::days(1)
            }
        }
        "weekly" => {
            let target_dow = sched.day_of_week.unwrap_or(0).clamp(0, 6) as u32;
            // chrono Weekday has Monday=0..Sunday=6 via num_days_from_monday
            let mut candidate = now
                .with_hour(hour)
                .and_then(|t| t.with_minute(minute))
                .and_then(|t| t.with_second(0))
                .and_then(|t| t.with_nanosecond(0))
                .unwrap_or(now);
            let now_dow = candidate.weekday().num_days_from_monday();
            let mut delta = (target_dow + 7 - now_dow) % 7;
            if delta == 0 && candidate <= now {
                delta = 7;
            }
            candidate += Duration::days(delta as i64);
            candidate
        }
        "monthly" => {
            let dom = sched.day_of_month.unwrap_or(1).clamp(1, 28) as u32;
            let mut year = now.year();
            let mut month = now.month();
            // Try this month first.
            let try_this_month = chrono::NaiveDate::from_ymd_opt(year, month, dom)
                .and_then(|d| d.and_hms_opt(hour, minute, 0))
                .and_then(|ndt| Utc.from_local_datetime(&ndt).single());
            if let Some(c) = try_this_month {
                if c > now {
                    return c;
                }
            }
            // Else, advance to next month.
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
            }
            chrono::NaiveDate::from_ymd_opt(year, month, dom)
                .and_then(|d| d.and_hms_opt(hour, minute, 0))
                .and_then(|ndt| Utc.from_local_datetime(&ndt).single())
                .unwrap_or_else(|| now + Duration::days(30))
        }
        // Unknown frequency: fail-safe to "tomorrow same time" so the
        // schedule doesn't loop hot.
        _ => now + Duration::days(1),
    }
}

// Suppress unused import warnings for code paths the compiler can't
// always see (NaiveDateTime, Weekday).
#[allow(dead_code)]
fn _imports_used(_: NaiveDateTime, _: Weekday) {}

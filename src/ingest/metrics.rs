//! Process-wide ingestion counters (Phase 2b — T8 observability).
//!
//! Cheap `AtomicU64` counters incremented on the hot ingest paths so an
//! operator can answer "is the pipeline keeping up at 10k hosts?" without
//! attaching a profiler. Surfaced as JSON (`/api/tc/ingest/stats`) and in
//! Prometheus text (`/metrics`) alongside the live queue depth. Counters are
//! cumulative since process start; rates are derived by the scraper from the
//! delta between two reads.
//!
//! `Relaxed` ordering is intentional: these are independent monotonic counters
//! with no inter-counter invariant to protect, so the cheapest atomic add is
//! the right call on a path that fires per webhook request.

use std::sync::atomic::{AtomicU64, Ordering};

static ENQUEUED: AtomicU64 = AtomicU64::new(0);
static PROCESSED: AtomicU64 = AtomicU64::new(0);
static BACKPRESSURE_REJECTED: AtomicU64 = AtomicU64::new(0);
static BATCH_FLUSHES: AtomicU64 = AtomicU64::new(0);
static ROWS_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// A payload was accepted on the hot path and write-ahead-queued.
#[inline]
pub fn inc_enqueued() {
    ENQUEUED.fetch_add(1, Ordering::Relaxed);
}

/// `n` queued payloads were drained + processed by a worker.
#[inline]
pub fn add_processed(n: u64) {
    PROCESSED.fetch_add(n, Ordering::Relaxed);
}

/// A payload was shed with 503 because the durable queue was over capacity.
#[inline]
pub fn inc_backpressure_rejected() {
    BACKPRESSURE_REJECTED.fetch_add(1, Ordering::Relaxed);
}

/// A batched log insert flushed `rows` rows (post-dedup count actually written).
#[inline]
pub fn add_batch_flush(rows: u64) {
    BATCH_FLUSHES.fetch_add(1, Ordering::Relaxed);
    ROWS_WRITTEN.fetch_add(rows, Ordering::Relaxed);
}

/// Immutable snapshot of every counter, for the stats endpoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IngestCounters {
    pub enqueued_total: u64,
    pub processed_total: u64,
    pub backpressure_rejected_total: u64,
    pub batch_flushes_total: u64,
    pub rows_written_total: u64,
}

/// Read all counters. Each load is `Relaxed`; the snapshot is not a consistent
/// instant across counters (a concurrent increment may land between loads), which
/// is fine for monitoring — the numbers are cumulative and self-correct.
pub fn snapshot() -> IngestCounters {
    IngestCounters {
        enqueued_total: ENQUEUED.load(Ordering::Relaxed),
        processed_total: PROCESSED.load(Ordering::Relaxed),
        backpressure_rejected_total: BACKPRESSURE_REJECTED.load(Ordering::Relaxed),
        batch_flushes_total: BATCH_FLUSHES.load(Ordering::Relaxed),
        rows_written_total: ROWS_WRITTEN.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Delta-based so it's robust regardless of any other code that touched the
    // global counters earlier in the run (these statics are only mutated here
    // and on the live ingest path, which the unit-test build never exercises).
    #[test]
    fn counters_increment() {
        let before = snapshot();
        inc_enqueued();
        add_processed(3);
        inc_backpressure_rejected();
        add_batch_flush(10);
        let after = snapshot();
        assert_eq!(after.enqueued_total - before.enqueued_total, 1);
        assert_eq!(after.processed_total - before.processed_total, 3);
        assert_eq!(
            after.backpressure_rejected_total - before.backpressure_rejected_total,
            1
        );
        assert_eq!(after.batch_flushes_total - before.batch_flushes_total, 1);
        assert_eq!(after.rows_written_total - before.rows_written_total, 10);
    }
}

//! Active scan enrichment pipeline.
//!
//! Connector skills sync data on schedule. The scan pipeline runs the
//! *active* counterparts (Nmap fingerprint, Trivy image scan, etc.)
//! out-of-band so the L2 forensic agent never blocks on them.
//!
//! Architecture:
//!
//! ```text
//! [hook in assets::merge / findings::create]
//!         │
//!         ▼
//!   queue::enqueue(target, scan_type, ttl_seconds)   (with TTL dedup)
//!         │
//!         ▼
//!   worker pool (3 workers, SELECT FOR UPDATE SKIP LOCKED)
//!         │
//!         ▼
//!   dispatcher → execute_skill / run_discovery → write result_json
//!         │
//!         ▼
//!   side effects: assets.properties enriched / findings inserted
//!         │
//!         ▼
//!   L2 reads via get_asset_info — never knew a scan ran.
//! ```
//!
//! See `migrations/V51__scan_queue.sql` for the table.

pub mod queue;
pub mod schedule;
pub mod worker;

pub use queue::{enqueue_nmap_fingerprint, enqueue_trivy_image};
pub use schedule::{compute_next_run, spawn_schedule_tick};
pub use worker::spawn_scan_workers;

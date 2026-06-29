//! Asynchronous ingestion (Phase 2a): a durable Postgres queue decouples the
//! webhook HTTP response from the parsing / Sigma / DB work, which now runs in a
//! background worker pool. See `worker.rs`.

pub mod metrics;
pub mod worker;
pub use worker::{spawn_fluentbit_drainer, spawn_ingest_workers};

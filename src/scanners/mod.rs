//! Scanner abstraction layer — orchestrates security tools.
//!
//! Each scanner can run in 3 modes:
//! - **Docker**: ThreatClaw manages the container (default)
//! - **LocalBinary**: Tool already installed on the machine
//! - **RemoteApi**: Tool running on another server
//!
//! The core calls the same `ScannerBackend` trait regardless of mode.

pub mod backend;
pub mod nuclei;
pub mod trivy;

pub use backend::{ScanResult, ScannerBackend, ScannerConfig, ScannerMode};

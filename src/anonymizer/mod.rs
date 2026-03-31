//! Data anonymizer for LLM-bound content.
//! Strips PII, internal IPs, hostnames, credentials before sending to cloud LLMs.
//!
//! Part of the ThreatClaw NIS2 compliance layer: sensitive data never leaves the
//! on-premise perimeter.  The anonymizer produces reversible placeholders so that
//! LLM responses can be de-anonymized before being shown to the analyst.

mod patterns;
mod transformer;

pub use transformer::{AnonymizeConfig, AnonymizeResult, AnonymizeStats, Anonymizer};

//! LibSQL stub implementation of `SentinelStore`.
//!
//! skill-microsoft-sentinel writes to PostgreSQL-only tables (V74 schema:
//! `sentinel_incident_metadata`, `sentinel_alerts`, `sentinel_entities`,
//! `sentinel_analytic_rules_cache`). The libsql backend exists so that
//! the `Database` super-trait is satisfied for embedded deployments, but
//! every method returns the standard "not supported" error so a misconfig
//! fails loudly instead of silently swallowing Sentinel data.

use chrono::{DateTime, Utc};
use std::collections::HashSet;
use uuid::Uuid;

use super::libsql::LibSqlBackend;
use crate::connectors::microsoft_sentinel::{
    DedupDecision, ParsedAnalyticRule, ParsedSentinelAlert, ParsedSentinelEntity,
    ParsedSentinelIncident, SentinelError, SentinelStore,
};

fn not_supported() -> SentinelError {
    SentinelError::Parse("skill-microsoft-sentinel requires PostgreSQL backend".to_string())
}

#[async_trait::async_trait]
impl SentinelStore for LibSqlBackend {
    async fn load_known_graph_provider_alert_ids(&self) -> Result<HashSet<String>, SentinelError> {
        Err(not_supported())
    }
    async fn load_cursor(&self) -> Result<Option<DateTime<Utc>>, SentinelError> {
        Err(not_supported())
    }
    async fn save_cursor(&self, _: DateTime<Utc>) -> Result<(), SentinelError> {
        Err(not_supported())
    }
    async fn upsert_incident_with_metadata(
        &self,
        _: &ParsedSentinelIncident,
        _: Uuid,
    ) -> Result<i32, SentinelError> {
        Err(not_supported())
    }
    async fn upsert_sentinel_alert(
        &self,
        _: i32,
        _: &ParsedSentinelAlert,
        _: DedupDecision,
    ) -> Result<(), SentinelError> {
        Err(not_supported())
    }
    async fn upsert_sentinel_entity(
        &self,
        _: i32,
        _: &ParsedSentinelEntity,
    ) -> Result<(), SentinelError> {
        Err(not_supported())
    }
    async fn upsert_analytic_rule(
        &self,
        _: Uuid,
        _: &ParsedAnalyticRule,
    ) -> Result<(), SentinelError> {
        Err(not_supported())
    }
    async fn maybe_get_cached_analytic_rule(
        &self,
        _: Uuid,
        _: Uuid,
        _: i64,
    ) -> Result<Option<ParsedAnalyticRule>, SentinelError> {
        Err(not_supported())
    }
}

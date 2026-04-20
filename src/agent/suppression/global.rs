//! Process-wide suppression engine. See ADR-047.

use super::engine::{CompileReport, SuppressionEngine};
use super::model::{RawRule, RuleAction, Scope};
use crate::db::threatclaw_store::ThreatClawStore;
use crate::error::DatabaseError;
use std::sync::{Arc, OnceLock};

static ENGINE: OnceLock<Arc<SuppressionEngine>> = OnceLock::new();

pub fn engine() -> Arc<SuppressionEngine> {
    ENGINE
        .get_or_init(|| Arc::new(SuppressionEngine::new()))
        .clone()
}

/// Pull active rules from the store and atomically swap the engine's
/// compiled set. Called at boot and after any CUD operation via the API.
pub async fn reload<S>(store: &S) -> Result<CompileReport, DatabaseError>
where
    S: ThreatClawStore + ?Sized,
{
    let rows = store.load_active_suppression_rules().await?;
    let mut raw = Vec::with_capacity(rows.len());
    for row in rows {
        match parse_row(&row) {
            Some(r) => raw.push(r),
            None => {
                tracing::warn!("SUPPRESSION: skipping malformed row: {}", row);
            }
        }
    }
    let report = engine().replace_rules(raw).await;
    tracing::info!(
        "SUPPRESSION: reloaded — {} compiled, {} failed, {} expired",
        report.compiled,
        report.failed_compile,
        report.skipped_expired
    );
    Ok(report)
}

fn parse_row(row: &serde_json::Value) -> Option<RawRule> {
    let id_str = row.get("id")?.as_str()?;
    let id = uuid::Uuid::parse_str(id_str).ok()?;
    let name = row.get("name")?.as_str()?.to_string();
    let predicate_source = row.get("predicate_source")?.as_str()?.to_string();
    let action = RuleAction::parse(row.get("action")?.as_str()?)?;
    let severity_cap = row
        .get("severity_cap")
        .and_then(|v| v.as_str())
        .map(String::from);
    let scope = Scope::parse(row.get("scope")?.as_str()?);
    let enabled = row.get("enabled")?.as_bool()?;
    let expires_at = row
        .get("expires_at")?
        .as_str()?
        .parse::<chrono::DateTime<chrono::Utc>>()
        .ok()?;
    Some(RawRule {
        id,
        name,
        predicate_source,
        action,
        severity_cap,
        scope,
        enabled,
        expires_at,
    })
}

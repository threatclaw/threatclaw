//! Hot-path suppression evaluation. See ADR-047.

use super::cel_exec;
use super::model::{CompiledRule, RawRule, RuleAction};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressionDecision {
    Keep,
    Drop { rule_id: uuid::Uuid },
    Downgrade { rule_id: uuid::Uuid, cap: String },
    Tag { rule_id: uuid::Uuid },
}

impl SuppressionDecision {
    pub fn matched_rule(&self) -> Option<uuid::Uuid> {
        match self {
            Self::Keep => None,
            Self::Drop { rule_id } | Self::Downgrade { rule_id, .. } | Self::Tag { rule_id } => {
                Some(*rule_id)
            }
        }
    }
}

/// Thread-safe engine. Reload via `replace_rules` on NOTIFY.
pub struct SuppressionEngine {
    rules: RwLock<Arc<Vec<CompiledRule>>>,
}

impl Default for SuppressionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SuppressionEngine {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Arc::new(Vec::new())),
        }
    }

    /// Compile raw rules and atomically replace the active set.
    /// Invalid CEL is logged and skipped — bad rules don't break the hot path.
    pub async fn replace_rules(&self, raw: Vec<RawRule>) -> CompileReport {
        let mut compiled = Vec::with_capacity(raw.len());
        let mut report = CompileReport::default();
        let now = chrono::Utc::now();

        for r in raw {
            if !r.enabled || r.expires_at <= now {
                report.skipped_expired += 1;
                continue;
            }
            match cel_exec::compile(&r.predicate_source) {
                Ok(program) => {
                    compiled.push(CompiledRule {
                        id: r.id,
                        program,
                        action: r.action,
                        severity_cap: r.severity_cap,
                        scope: r.scope,
                    });
                    report.compiled += 1;
                }
                Err(e) => {
                    tracing::warn!("SUPPRESSION: rule {} CEL compile failed: {}", r.id, e);
                    report.failed_compile += 1;
                }
            }
        }

        *self.rules.write().await = Arc::new(compiled);
        report
    }

    /// Evaluate event against active rules. Returns the first match in
    /// insertion order (most-recently-reloaded = most-recently-created).
    pub async fn evaluate(
        &self,
        event: &JsonValue,
        skill_id: &str,
        asset_group: Option<&str>,
    ) -> SuppressionDecision {
        let rules = self.rules.read().await.clone();
        for rule in rules.iter() {
            if !rule.scope.matches(skill_id, asset_group) {
                continue;
            }
            match cel_exec::evaluate(&rule.program, event) {
                Ok(true) => {
                    return match rule.action {
                        RuleAction::Drop => SuppressionDecision::Drop { rule_id: rule.id },
                        RuleAction::Downgrade => SuppressionDecision::Downgrade {
                            rule_id: rule.id,
                            cap: rule
                                .severity_cap
                                .clone()
                                .unwrap_or_else(|| "LOW".to_string()),
                        },
                        RuleAction::Tag => SuppressionDecision::Tag { rule_id: rule.id },
                    };
                }
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!("SUPPRESSION: rule {} eval error (skipped): {}", rule.id, e);
                    continue;
                }
            }
        }
        SuppressionDecision::Keep
    }

    pub async fn rule_count(&self) -> usize {
        self.rules.read().await.len()
    }
}

#[derive(Debug, Default, Clone)]
pub struct CompileReport {
    pub compiled: usize,
    pub failed_compile: usize,
    pub skipped_expired: usize,
}

#[cfg(test)]
mod tests {
    use super::super::model::{RawRule, RuleAction, Scope};
    use super::*;
    use chrono::{Duration, Utc};

    fn mk_rule(source: &str, action: RuleAction, scope: Scope, expires_in_days: i64) -> RawRule {
        RawRule {
            id: uuid::Uuid::new_v4(),
            name: "test".into(),
            predicate_source: source.into(),
            action,
            severity_cap: None,
            scope,
            enabled: true,
            expires_at: Utc::now() + Duration::days(expires_in_days),
        }
    }

    fn event() -> JsonValue {
        serde_json::json!({
            "skill_id": "skill-suricata",
            "category": "port_scan",
            "severity": "MEDIUM",
            "src_ip": "10.0.5.42",
            "asset": "host-x",
        })
    }

    #[tokio::test]
    async fn drop_on_match() {
        let eng = SuppressionEngine::new();
        eng.replace_rules(vec![mk_rule(
            r#"event.category == "port_scan""#,
            RuleAction::Drop,
            Scope::Global,
            90,
        )])
        .await;
        let d = eng.evaluate(&event(), "skill-suricata", None).await;
        assert!(matches!(d, SuppressionDecision::Drop { .. }));
    }

    #[tokio::test]
    async fn keep_when_no_match() {
        let eng = SuppressionEngine::new();
        eng.replace_rules(vec![mk_rule(
            r#"event.category == "brute_force""#,
            RuleAction::Drop,
            Scope::Global,
            90,
        )])
        .await;
        assert_eq!(
            eng.evaluate(&event(), "skill-suricata", None).await,
            SuppressionDecision::Keep
        );
    }

    #[tokio::test]
    async fn downgrade_keeps_event_with_cap() {
        let eng = SuppressionEngine::new();
        let mut r = mk_rule(
            r#"event.severity == "MEDIUM""#,
            RuleAction::Downgrade,
            Scope::Global,
            90,
        );
        r.severity_cap = Some("LOW".into());
        eng.replace_rules(vec![r]).await;
        match eng.evaluate(&event(), "skill-suricata", None).await {
            SuppressionDecision::Downgrade { cap, .. } => assert_eq!(cap, "LOW"),
            other => panic!("expected Downgrade, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn expired_rule_is_skipped() {
        let eng = SuppressionEngine::new();
        let report = eng
            .replace_rules(vec![mk_rule(
                r#"event.category == "port_scan""#,
                RuleAction::Drop,
                Scope::Global,
                -1, // expired yesterday
            )])
            .await;
        assert_eq!(report.compiled, 0);
        assert_eq!(report.skipped_expired, 1);
        assert_eq!(
            eng.evaluate(&event(), "skill-suricata", None).await,
            SuppressionDecision::Keep
        );
    }

    #[tokio::test]
    async fn scope_skill_filters_correctly() {
        let eng = SuppressionEngine::new();
        eng.replace_rules(vec![mk_rule(
            r#"event.category == "port_scan""#,
            RuleAction::Drop,
            Scope::Skill("skill-zeek".into()),
            90,
        )])
        .await;
        assert_eq!(
            eng.evaluate(&event(), "skill-suricata", None).await,
            SuppressionDecision::Keep
        );
        assert!(matches!(
            eng.evaluate(&event(), "skill-zeek", None).await,
            SuppressionDecision::Drop { .. }
        ));
    }

    #[tokio::test]
    async fn invalid_cel_is_counted_not_thrown() {
        let eng = SuppressionEngine::new();
        let report = eng
            .replace_rules(vec![
                mk_rule(
                    "event. broken syntax [",
                    RuleAction::Drop,
                    Scope::Global,
                    90,
                ),
                mk_rule(
                    r#"event.category == "port_scan""#,
                    RuleAction::Drop,
                    Scope::Global,
                    90,
                ),
            ])
            .await;
        assert_eq!(report.compiled, 1);
        assert_eq!(report.failed_compile, 1);
        assert!(matches!(
            eng.evaluate(&event(), "skill-suricata", None).await,
            SuppressionDecision::Drop { .. }
        ));
    }

    #[tokio::test]
    async fn eval_error_on_missing_field_skips_rule() {
        let eng = SuppressionEngine::new();
        eng.replace_rules(vec![
            mk_rule(
                "event.does_not_exist == 1",
                RuleAction::Drop,
                Scope::Global,
                90,
            ),
            mk_rule(
                r#"event.category == "port_scan""#,
                RuleAction::Drop,
                Scope::Global,
                90,
            ),
        ])
        .await;
        assert!(matches!(
            eng.evaluate(&event(), "skill-suricata", None).await,
            SuppressionDecision::Drop { .. }
        ));
    }
}

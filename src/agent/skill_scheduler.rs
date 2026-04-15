//! Skill Scheduler — configurable cron per skill.
//!
//! Each skill can have its own schedule (cron expression) stored in the DB.
//! The scheduler checks every minute which skills need to run.
//! Replaces the global scheduler with per-skill granularity.

use crate::db::Database;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// A skill schedule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSchedule {
    pub skill_id: String,
    pub enabled: bool,
    pub cron: String, // Cron expression (e.g., "0 2 * * *")
    pub description: String,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
}

/// Default schedules for built-in skills.
pub fn default_schedules() -> Vec<SkillSchedule> {
    vec![
        // Legacy Python skills disabled — moved to _future/, not functional.
        // Re-enable when reimplemented as Rust/Docker skills.
        SkillSchedule {
            skill_id: "skill-email-audit".into(),
            enabled: true,
            cron: "0 8 * * 1".into(),
            description: "Audit email chaque lundi à 8h".into(),
            last_run: None,
            next_run: None,
        },
        // NIS2/ISO compliance will move to a dedicated Compliance page
        SkillSchedule {
            skill_id: "skill-report-gen".into(),
            enabled: true,
            cron: "0 8 * * 5".into(),
            description: "Rapport hebdomadaire vendredi à 8h".into(),
            last_run: None,
            next_run: None,
        },
    ]
}

/// Load skill schedules from DB (or defaults if not configured).
pub async fn load_schedules(store: &dyn Database) -> Vec<SkillSchedule> {
    if let Ok(Some(val)) = store.get_setting("_system", "skill_schedules").await {
        if let Ok(schedules) = serde_json::from_value(val) {
            return schedules;
        }
    }

    // Return defaults and persist them
    let defaults = default_schedules();
    let _ = store
        .set_setting(
            "_system",
            "skill_schedules",
            &serde_json::to_value(&defaults).unwrap_or_default(),
        )
        .await;
    defaults
}

/// Save skill schedules to DB.
pub async fn save_schedules(
    store: &dyn Database,
    schedules: &[SkillSchedule],
) -> Result<(), String> {
    store
        .set_setting(
            "_system",
            "skill_schedules",
            &serde_json::to_value(schedules).unwrap_or_default(),
        )
        .await
        .map_err(|e| e.to_string())
}

/// Check if a skill should run now based on its cron expression.
/// Simple cron matching: minute hour day_of_month month day_of_week
pub fn should_run_now(cron: &str, now: &chrono::DateTime<chrono::Utc>) -> bool {
    let parts: Vec<&str> = cron.split_whitespace().collect();
    if parts.len() != 5 {
        return false;
    }

    let matches_field = |field: &str, value: u32| -> bool {
        if field == "*" {
            return true;
        }
        if field.starts_with("*/") {
            if let Ok(step) = field[2..].parse::<u32>() {
                return step > 0 && value % step == 0;
            }
        }
        if let Ok(exact) = field.parse::<u32>() {
            return value == exact;
        }
        // Comma-separated values
        field
            .split(',')
            .any(|v| v.parse::<u32>().ok() == Some(value))
    };

    matches_field(parts[0], now.format("%M").to_string().parse().unwrap_or(99))
        && matches_field(parts[1], now.format("%H").to_string().parse().unwrap_or(99))
        && matches_field(parts[2], now.format("%d").to_string().parse().unwrap_or(99))
        && matches_field(parts[3], now.format("%m").to_string().parse().unwrap_or(99))
        && matches_field(parts[4], now.format("%u").to_string().parse().unwrap_or(99)) // 1=Mon..7=Sun
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_run() {
        // Create a fixed time: Tuesday 2026-03-24 14:00:00 UTC
        // (2026-03-23 is a Monday — prior version had an off-by-one in the comment)
        let now = chrono::DateTime::parse_from_rfc3339("2026-03-24T14:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert!(should_run_now("0 14 * * *", &now)); // Every day at 14:00
        assert!(should_run_now("0 * * * *", &now)); // Every hour at :00
        assert!(should_run_now("* * * * *", &now)); // Every minute
        assert!(!should_run_now("30 14 * * *", &now)); // 14:30 not 14:00
        assert!(!should_run_now("0 15 * * *", &now)); // 15:00 not 14:00
        assert!(should_run_now("0 14 24 * *", &now)); // 24th at 14:00
        assert!(should_run_now("0 14 * * 2", &now)); // Tuesday at 14:00
    }

    #[test]
    fn test_cron_step() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-03-23T06:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(should_run_now("0 */6 * * *", &now)); // Every 6h at :00
        assert!(should_run_now("0 */2 * * *", &now)); // Every 2h at :00
    }

    #[test]
    fn test_defaults() {
        let defaults = default_schedules();
        assert!(!defaults.is_empty());
        assert!(defaults.iter().any(|s| s.skill_id == "skill-email-audit"));
    }
}

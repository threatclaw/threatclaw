//! Cyber Scheduler — default security routines. See ADR-030.

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent::routine::{NotifyConfig, Routine, RoutineAction, RoutineGuardrails, Trigger};
use crate::db::RoutineStore;

/// Configuration for cyber-specific scheduling, loaded from threatclaw.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberSchedulerConfig {
    /// Whether to auto-create default security routines on first boot.
    pub auto_create_defaults: bool,
    /// Owner ID for auto-created routines.
    pub owner_id: String,
    /// Cron schedules (overridable via threatclaw.toml [scheduler] section).
    pub schedules: CyberSchedules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberSchedules {
    pub vuln_scan_daily: String,
    pub darkweb_check: String,
    pub cloud_posture_weekly: String,
    pub log_analysis: String,
    pub phishing_monthly: String,
    pub report_weekly: String,
}

impl Default for CyberSchedules {
    fn default() -> Self {
        Self {
            vuln_scan_daily: "0 2 * * *".to_string(),
            darkweb_check: "0 */6 * * *".to_string(),
            cloud_posture_weekly: "0 3 * * 1".to_string(),
            log_analysis: "*/5 * * * *".to_string(),
            phishing_monthly: "0 10 1 * *".to_string(),
            report_weekly: "0 8 * * 5".to_string(),
        }
    }
}

impl Default for CyberSchedulerConfig {
    fn default() -> Self {
        Self {
            auto_create_defaults: true,
            owner_id: "default".to_string(),
            schedules: CyberSchedules::default(),
        }
    }
}

/// Definitions for each default cyber routine.
struct CyberRoutineTemplate {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    schedule_fn: fn(&CyberSchedules) -> &str,
    prompt: &'static str,
    max_iterations: u32,
    cooldown_secs: u64,
}

const CYBER_ROUTINES: &[CyberRoutineTemplate] = &[
    CyberRoutineTemplate {
        name: "threatclaw-vuln-scan",
        title: "Scan de vulnérabilités quotidien",
        description: "Scan quotidien de vulnérabilités (Nuclei + Grype + EPSS)",
        schedule_fn: |s| &s.vuln_scan_daily,
        prompt: r#"Execute a comprehensive vulnerability scan:
1. Run Nuclei network scan against configured targets
2. Run Grype container image scan against deployed images
3. Enrich findings with EPSS scores for real-world prioritization
4. Deduplicate and prioritize findings (CVSS * EPSS)
5. Store results in database
6. Alert on any CRITICAL or HIGH findings with EPSS > 0.5

Focus on actionable findings. Skip informational-only results."#,
        max_iterations: 10,
        cooldown_secs: 3600,
    },
    CyberRoutineTemplate {
        name: "threatclaw-darkweb-monitor",
        title: "Surveillance dark web",
        description: "Surveillance dark web — fuites d'identifiants (HIBP)",
        schedule_fn: |s| &s.darkweb_check,
        prompt: r#"Check for credential leaks and data breaches:
1. Query HIBP API for configured email domains
2. Check for new breaches since last scan
3. Assess breach criticality (recent + verified = CRITICAL)
4. Anonymize email addresses in results
5. Store findings and alert on new CRITICAL breaches

Rate limit: respect 1.6s between API calls."#,
        max_iterations: 5,
        cooldown_secs: 1800,
    },
    CyberRoutineTemplate {
        name: "threatclaw-cloud-posture",
        title: "Audit posture cloud hebdomadaire",
        description: "Audit hebdomadaire de posture cloud (Prowler AWS/Azure/GCP)",
        schedule_fn: |s| &s.cloud_posture_weekly,
        prompt: r#"Run cloud security posture assessment:
1. Execute Prowler scan against configured cloud provider
2. Map findings to NIS2 Art.21 compliance requirements
3. Map findings to ISO 27001 controls (if configured)
4. Calculate security score (weighted by severity)
5. Compare with previous scan for drift detection
6. Generate summary with top 10 critical findings
7. Alert on score decrease > 5 points

Output NIS2 compliance mapping per article section."#,
        max_iterations: 10,
        cooldown_secs: 7200,
    },
    CyberRoutineTemplate {
        name: "threatclaw-soc-monitor",
        title: "Analyse SOC continue",
        description: "Analyse continue des logs SOC (Sigma rules + triage)",
        schedule_fn: |s| &s.log_analysis,
        prompt: r#"Analyze recent security logs:
1. Fetch logs from PostgreSQL (last 5 minutes)
2. Apply enabled Sigma rules to detect threats
3. Correlate alerts (same source, brute force, lateral movement)
4. Triage alerts to estimate false positive probability
5. Store alerts with severity and correlation data
6. Alert on CRITICAL correlations (brute force, lateral movement)

Skip informational-only alerts. Focus on actionable security events."#,
        max_iterations: 5,
        cooldown_secs: 60,
    },
    CyberRoutineTemplate {
        name: "threatclaw-phishing-sim",
        title: "Simulation phishing mensuelle",
        description: "Campagne mensuelle de simulation phishing (GoPhish)",
        schedule_fn: |s| &s.phishing_monthly,
        prompt: r#"Prepare a phishing simulation campaign:
1. Generate contextual phishing template using LLM
2. Select template type based on rotation (CEO fraud, IT support, HR notice)
3. Create campaign in GoPhish with employee target group
4. Wait for approval before launching (human-in-the-loop required)
5. Monitor campaign results after 48h
6. Generate awareness report with click rates and training recommendations

IMPORTANT: Requires human approval before launch. Never auto-launch."#,
        max_iterations: 8,
        cooldown_secs: 86400,
    },
    CyberRoutineTemplate {
        name: "threatclaw-weekly-report",
        title: "Rapport hebdomadaire",
        description: "Rapport hebdomadaire (synthèse + NIS2)",
        schedule_fn: |s| &s.report_weekly,
        prompt: r#"Generate the weekly RSSI security report:
1. Aggregate vulnerability scan results from the past week
2. Aggregate SOC alerts (total, by severity, false positive rate)
3. Include cloud posture score and drift
4. Include dark web monitoring summary
5. Calculate overall security score
6. Map findings to NIS2 Art.21 compliance sections
7. Generate executive summary in French
8. Store report and notify RSSI

Report format: PDF-ready with sections for each NIS2 article."#,
        max_iterations: 10,
        cooldown_secs: 3600,
    },
    CyberRoutineTemplate {
        name: "threatclaw-retention-cleanup",
        title: "Nettoyage rétention données",
        description: "Nettoyage nocturne des données expirées selon la politique de rétention",
        schedule_fn: |_| "30 3 * * *", // 03h30 chaque nuit
        prompt: r#"Run data retention cleanup:
1. Execute SELECT * FROM run_retention_cleanup() to clean expired data
2. Report the number of rows deleted per table
3. Check database size and alert if > 80% of configured limit

This is a maintenance task — no user interaction needed."#,
        max_iterations: 3,
        cooldown_secs: 43200, // 12h cooldown
    },
    CyberRoutineTemplate {
        name: "threatclaw-heartbeat",
        title: "Heartbeat — surveillance proactive",
        description: "Vérification proactive toutes les 30 minutes",
        schedule_fn: |_| "*/30 * * * *",
        prompt: r#"Run heartbeat checks as defined in HEARTBEAT.md:
1. Check for critical findings with status=open
2. Verify AGENT_SOUL.toml integrity (hash check)
3. Test connectivity to configured targets
4. Check service health (PostgreSQL, Ollama, Fluent Bit)
5. Check log volume anomalies

Report findings as alerts. Never execute corrective actions.
If critical issues found, notify RSSI via configured channel."#,
        max_iterations: 3,
        cooldown_secs: 900,
    },
];

/// Build a Routine from a template and schedule config.
fn build_routine(template: &CyberRoutineTemplate, config: &CyberSchedulerConfig) -> Routine {
    let schedule = (template.schedule_fn)(&config.schedules);
    let now = Utc::now();

    Routine {
        id: Uuid::new_v4(),
        name: template.name.to_string(),
        description: template.description.to_string(),
        user_id: config.owner_id.clone(),
        enabled: true,
        trigger: Trigger::Cron {
            schedule: schedule.to_string(),
            timezone: None,
        },
        action: RoutineAction::FullJob {
            title: template.title.to_string(),
            description: template.prompt.to_string(),
            max_iterations: template.max_iterations,
            tool_permissions: vec![],
        },
        guardrails: RoutineGuardrails {
            cooldown: Duration::from_secs(template.cooldown_secs),
            max_concurrent: 1,
            dedup_window: None,
        },
        notify: NotifyConfig {
            channel: None,
            user: None,
            on_attention: true,
            on_failure: true,
            on_success: false,
        },
        last_run_at: None,
        next_fire_at: None,
        run_count: 0,
        consecutive_failures: 0,
        state: serde_json::Value::Null,
        created_at: now,
        updated_at: now,
    }
}

/// Initialize default cyber routines in the database if they don't already exist.
///
/// Called during application bootstrap. Checks by routine name to avoid duplicates.
pub async fn ensure_default_routines(
    store: &dyn RoutineStore,
    config: &CyberSchedulerConfig,
) -> Result<usize, crate::error::DatabaseError> {
    if !config.auto_create_defaults {
        tracing::info!("Cyber scheduler: auto-create disabled, skipping");
        return Ok(0);
    }

    let mut created = 0;

    for template in CYBER_ROUTINES {
        // Check if routine already exists by name
        match store
            .get_routine_by_name(&config.owner_id, template.name)
            .await
        {
            Ok(Some(_)) => {
                tracing::debug!("Cyber routine '{}' already exists, skipping", template.name);
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Failed to check routine '{}': {}, skipping",
                    template.name,
                    e
                );
                continue;
            }
        }

        let routine = build_routine(template, config);

        match store.create_routine(&routine).await {
            Ok(_) => {
                tracing::info!(
                    "Created cyber routine '{}' (schedule: {})",
                    template.name,
                    match &routine.trigger {
                        Trigger::Cron { schedule, .. } => schedule.as_str(),
                        _ => "n/a",
                    }
                );
                created += 1;
            }
            Err(e) => {
                tracing::warn!("Failed to create routine '{}': {}", template.name, e);
            }
        }
    }

    if created > 0 {
        tracing::info!(
            "Cyber scheduler: created {} default security routines",
            created
        );
    }

    Ok(created)
}

/// Returns all default routine names for status checking.
pub fn default_routine_names() -> Vec<&'static str> {
    CYBER_ROUTINES.iter().map(|r| r.name).collect()
}

/// Returns the number of default cyber routines.
pub fn default_routine_count() -> usize {
    CYBER_ROUTINES.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CyberSchedulerConfig::default();
        assert!(config.auto_create_defaults);
        assert_eq!(config.owner_id, "default");
        assert_eq!(config.schedules.vuln_scan_daily, "0 2 * * *");
        assert_eq!(config.schedules.log_analysis, "*/5 * * * *");
    }

    #[test]
    fn test_default_schedules() {
        let s = CyberSchedules::default();
        assert_eq!(s.vuln_scan_daily, "0 2 * * *");
        assert_eq!(s.darkweb_check, "0 */6 * * *");
        assert_eq!(s.cloud_posture_weekly, "0 3 * * 1");
        assert_eq!(s.log_analysis, "*/5 * * * *");
        assert_eq!(s.phishing_monthly, "0 10 1 * *");
        assert_eq!(s.report_weekly, "0 8 * * 5");
    }

    #[test]
    fn test_build_routine_vuln_scan() {
        let config = CyberSchedulerConfig::default();
        let routine = build_routine(&CYBER_ROUTINES[0], &config);

        assert_eq!(routine.name, "threatclaw-vuln-scan");
        assert!(routine.enabled);
        assert_eq!(routine.user_id, "default");

        match &routine.trigger {
            Trigger::Cron { schedule, .. } => {
                assert_eq!(schedule, "0 2 * * *");
            }
            _ => panic!("Expected cron trigger"),
        }

        match &routine.action {
            RoutineAction::FullJob {
                title,
                max_iterations,
                ..
            } => {
                assert_eq!(title, "Scan de vulnérabilités quotidien");
                assert_eq!(*max_iterations, 10);
            }
            _ => panic!("Expected FullJob action"),
        }

        assert_eq!(routine.guardrails.cooldown.as_secs(), 3600);
    }

    #[test]
    fn test_build_routine_phishing_long_cooldown() {
        let config = CyberSchedulerConfig::default();
        let routine = build_routine(&CYBER_ROUTINES[4], &config);

        assert_eq!(routine.name, "threatclaw-phishing-sim");
        assert_eq!(routine.guardrails.cooldown.as_secs(), 86400);
    }

    #[test]
    fn test_build_routine_soc_monitor() {
        let config = CyberSchedulerConfig::default();
        let routine = build_routine(&CYBER_ROUTINES[3], &config);

        assert_eq!(routine.name, "threatclaw-soc-monitor");
        assert_eq!(routine.guardrails.cooldown.as_secs(), 60);
        assert_eq!(routine.guardrails.max_concurrent, 1);
    }

    #[test]
    fn test_build_routine_custom_schedule() {
        let mut config = CyberSchedulerConfig::default();
        config.schedules.vuln_scan_daily = "0 4 * * *".to_string();
        let routine = build_routine(&CYBER_ROUTINES[0], &config);

        match &routine.trigger {
            Trigger::Cron { schedule, .. } => {
                assert_eq!(schedule, "0 4 * * *");
            }
            _ => panic!("Expected cron trigger"),
        }
    }

    #[test]
    fn test_build_routine_custom_owner() {
        let mut config = CyberSchedulerConfig::default();
        config.owner_id = "client-abc".to_string();
        let routine = build_routine(&CYBER_ROUTINES[0], &config);

        assert_eq!(routine.user_id, "client-abc");
    }

    #[test]
    fn test_default_routine_names() {
        let names = default_routine_names();
        assert_eq!(names.len(), 8);
        assert!(names.contains(&"threatclaw-vuln-scan"));
        assert!(names.contains(&"threatclaw-darkweb-monitor"));
        assert!(names.contains(&"threatclaw-cloud-posture"));
        assert!(names.contains(&"threatclaw-soc-monitor"));
        assert!(names.contains(&"threatclaw-phishing-sim"));
        assert!(names.contains(&"threatclaw-weekly-report"));
    }

    #[test]
    fn test_default_routine_count() {
        assert_eq!(default_routine_count(), 8);
    }

    #[test]
    fn test_all_routines_are_full_job() {
        let config = CyberSchedulerConfig::default();
        for template in CYBER_ROUTINES {
            let routine = build_routine(template, &config);
            assert!(
                matches!(routine.action, RoutineAction::FullJob { .. }),
                "{} should be FullJob",
                template.name
            );
        }
    }

    #[test]
    fn test_all_routines_unique_names() {
        let names: Vec<_> = CYBER_ROUTINES.iter().map(|r| r.name).collect();
        let mut unique = names.clone();
        unique.dedup();
        assert_eq!(names.len(), unique.len(), "Duplicate routine names found");
    }

    #[test]
    fn test_all_routines_have_description() {
        for template in CYBER_ROUTINES {
            assert!(
                !template.description.is_empty(),
                "{} has empty description",
                template.name
            );
            assert!(
                !template.prompt.is_empty(),
                "{} has empty prompt",
                template.name
            );
        }
    }

    #[test]
    fn test_weekly_report_routine() {
        let config = CyberSchedulerConfig::default();
        let routine = build_routine(&CYBER_ROUTINES[5], &config);

        assert_eq!(routine.name, "threatclaw-weekly-report");
        match &routine.trigger {
            Trigger::Cron { schedule, .. } => {
                assert_eq!(schedule, "0 8 * * 5"); // Fridays 08:00
            }
            _ => panic!("Expected cron trigger"),
        }
    }

    #[test]
    fn test_disabled_auto_create() {
        let mut config = CyberSchedulerConfig::default();
        config.auto_create_defaults = false;
        assert!(!config.auto_create_defaults);
    }

    #[test]
    fn test_notify_config_defaults() {
        let config = CyberSchedulerConfig::default();
        let routine = build_routine(&CYBER_ROUTINES[0], &config);

        assert!(routine.notify.on_attention);
        assert!(routine.notify.on_failure);
        assert!(!routine.notify.on_success);
        assert!(routine.notify.channel.is_none());
    }

    #[test]
    fn test_guardrails_no_dedup() {
        let config = CyberSchedulerConfig::default();
        for template in CYBER_ROUTINES {
            let routine = build_routine(template, &config);
            assert!(
                routine.guardrails.dedup_window.is_none(),
                "{} should have no dedup window",
                template.name
            );
        }
    }
}

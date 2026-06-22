//! Risk-Based Aggregation — the RBA aggregator (Phase D1).
//!
//! Rules tagged `tier='rba_only'` don't raise direct alerts; each match writes a
//! weighted `risk_event` on a risk object (asset). This aggregator runs each IE
//! cycle, groups the recent risk events per object, and raises a single "risk
//! notable" incident when accumulated risk crosses a threshold — via the two
//! Risk Incident Rules (RIR) from the Splunk RBA model:
//!
//!   RIR (a) — score sum: `SUM(score)` over 24h `>= score_threshold`.
//!   RIR (b) — tactic diversity: `>= min_tactics` distinct MITRE tactics over 7d
//!             (catches low-and-slow attacks that span the kill chain even when
//!             the raw score stays modest).
//!
//! The aggregation + RIR evaluation are pure functions (no clock, no I/O) so they
//! are unit-tested. See internal/PLAN_PHASE_D_RBA.md.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};

use crate::db::Database;
use crate::db::threatclaw_store::RiskEvent;

/// Full lookback fetched once per run (covers the widest RIR window = 7d).
const WINDOW_FULL_HOURS: i64 = 168;
/// Window for the score-sum RIR (a).
const SCORE_WINDOW_HOURS: i64 = 24;
const DEFAULT_SCORE_THRESHOLD: i64 = 100;
const DEFAULT_MIN_TACTICS: usize = 3;

/// Tunable thresholds (read from settings, falls back to defaults). Calibration
/// is operator-driven on real data — cf. RBA best practice (don't guess seuils).
#[derive(Debug, Clone)]
pub struct RbaConfig {
    pub score_threshold: i64,
    pub min_tactics: usize,
}

impl Default for RbaConfig {
    fn default() -> Self {
        Self {
            score_threshold: DEFAULT_SCORE_THRESHOLD,
            min_tactics: DEFAULT_MIN_TACTICS,
        }
    }
}

impl RbaConfig {
    /// Load from `_system` settings, clamped to sane bounds; defaults on miss.
    pub async fn from_settings(store: &dyn Database) -> Self {
        let mut cfg = Self::default();
        if let Ok(Some(v)) = store
            .get_setting("_system", "tc_config_rba_score_threshold")
            .await
            && let Some(n) = v.as_i64()
        {
            cfg.score_threshold = n.clamp(10, 100_000);
        }
        if let Ok(Some(v)) = store
            .get_setting("_system", "tc_config_rba_min_tactics")
            .await
            && let Some(n) = v.as_i64()
        {
            cfg.min_tactics = n.clamp(2, 20) as usize;
        }
        cfg
    }
}

/// Per-object windowed risk, computed from the recent risk events.
#[derive(Debug, Clone)]
pub struct ObjectRisk {
    pub object: String,
    pub object_type: String,
    pub score_24h: i64,
    pub n_events_24h: usize,
    pub distinct_tactics_7d: usize,
    pub tactics_7d: Vec<String>,
    pub rules_24h: Vec<String>,
    /// Ids of every event (full 7d window) that contributed to this object. When
    /// a notable fires, these are marked consumed so they can't re-fire it.
    pub event_ids: Vec<i64>,
}

/// Which Risk Incident Rule fired for an object (if any).
#[derive(Debug, Clone, PartialEq)]
pub enum RirTrigger {
    /// RIR (a) — accumulated score over 24h crossed the threshold.
    ScoreThreshold { score: i64 },
    /// RIR (b) — distinct MITRE tactics over 7d crossed the minimum.
    TacticDiversity { tactics: usize },
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Pure: group risk events by object and compute the windowed stats. `now` is
/// passed in (no clock read) for deterministic tests. Events are assumed to be
/// within the 7d window (the caller fetches `WINDOW_FULL_HOURS`).
pub fn aggregate_by_object(events: &[RiskEvent], now: DateTime<Utc>) -> Vec<ObjectRisk> {
    use std::collections::HashMap;
    let cutoff_24h = now - Duration::hours(SCORE_WINDOW_HOURS);

    struct Acc {
        object_type: String,
        score_24h: i64,
        n_events_24h: usize,
        rules_24h: HashSet<String>,
        tactics_7d: HashSet<String>,
        event_ids: Vec<i64>,
    }
    let mut map: HashMap<String, Acc> = HashMap::new();

    for e in events {
        let acc = map.entry(e.risk_object.clone()).or_insert_with(|| Acc {
            object_type: e.object_type.clone(),
            score_24h: 0,
            n_events_24h: 0,
            rules_24h: HashSet::new(),
            tactics_7d: HashSet::new(),
            event_ids: Vec::new(),
        });
        // Every contributing event (whole window) is banked for consumption, so a
        // fired notable takes ALL of an object's accumulated risk out of the pool
        // — an older 7d event can't survive to re-fire the tactic-diversity RIR.
        acc.event_ids.push(e.id);
        // 7d window (all fetched events) — feeds the tactic-diversity RIR.
        if let Some(t) = &e.mitre_tactic
            && !t.is_empty()
        {
            acc.tactics_7d.insert(t.clone());
        }
        // 24h window — feeds the score-sum RIR. Unparseable timestamps are
        // conservatively treated as outside the 24h window (7d still counts them).
        if parse_ts(&e.created_at).is_some_and(|ts| ts >= cutoff_24h) {
            acc.score_24h += e.score as i64;
            acc.n_events_24h += 1;
            acc.rules_24h.insert(e.source_rule.clone());
        }
    }

    map.into_iter()
        .map(|(object, a)| {
            let mut tactics: Vec<String> = a.tactics_7d.into_iter().collect();
            tactics.sort();
            let mut rules: Vec<String> = a.rules_24h.into_iter().collect();
            rules.sort();
            ObjectRisk {
                object,
                object_type: a.object_type,
                score_24h: a.score_24h,
                n_events_24h: a.n_events_24h,
                distinct_tactics_7d: tactics.len(),
                tactics_7d: tactics,
                rules_24h: rules,
                event_ids: a.event_ids,
            }
        })
        .collect()
}

/// Pure: which RIR (if any) fires for an object given the config. Score RIR is
/// checked first (higher confidence), then tactic diversity.
pub fn evaluate_rirs(obj: &ObjectRisk, cfg: &RbaConfig) -> Option<RirTrigger> {
    if obj.score_24h >= cfg.score_threshold {
        return Some(RirTrigger::ScoreThreshold {
            score: obj.score_24h,
        });
    }
    if obj.distinct_tactics_7d >= cfg.min_tactics {
        return Some(RirTrigger::TacticDiversity {
            tactics: obj.distinct_tactics_7d,
        });
    }
    None
}

/// Severity of the risk notable: a score far past threshold (or broad
/// kill-chain coverage) is critical, otherwise high.
fn severity_for(trigger: &RirTrigger, cfg: &RbaConfig) -> &'static str {
    match trigger {
        RirTrigger::ScoreThreshold { score } if *score >= cfg.score_threshold * 2 => "critical",
        RirTrigger::TacticDiversity { tactics } if *tactics >= cfg.min_tactics + 2 => "critical",
        _ => "high",
    }
}

/// Run one aggregation pass. Called each IE cycle. Non-fatal: any error logs and
/// returns (RBA must never break the cycle).
pub async fn run_risk_aggregation(store: Arc<dyn Database>) {
    let events = match store.list_recent_risk_events(WINDOW_FULL_HOURS).await {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("RBA: list_recent_risk_events failed (or unsupported): {e}");
            return;
        }
    };
    if events.is_empty() {
        return;
    }
    let cfg = RbaConfig::from_settings(store.as_ref()).await;
    let now = Utc::now();
    let objects = aggregate_by_object(&events, now);

    for obj in objects {
        let Some(trigger) = evaluate_rirs(&obj, &cfg) else {
            continue;
        };

        // Dedup: don't pile a risk notable on an asset that already has an open
        // incident (risk or regular). A fresh notable is created once the prior
        // one is resolved/closed.
        match store.find_open_incident_for_asset(&obj.object).await {
            Ok(Some(_)) => {
                tracing::debug!(
                    "RBA: {} already has an open incident — risk notable skipped",
                    obj.object
                );
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "RBA: find_open_incident_for_asset failed for {}: {e}",
                    obj.object
                );
                continue;
            }
        }

        let severity = severity_for(&trigger, &cfg);
        let (title, reason) = match &trigger {
            RirTrigger::ScoreThreshold { score } => (
                format!("Risque accumulé sur {} (score {})", obj.object, score),
                format!(
                    "{} signaux faibles convergents sur 24h ({} règles) — score {} ≥ seuil {}",
                    obj.n_events_24h,
                    obj.rules_24h.len(),
                    score,
                    cfg.score_threshold
                ),
            ),
            RirTrigger::TacticDiversity { tactics } => (
                format!(
                    "Kill-chain multi-tactiques sur {} ({} tactiques)",
                    obj.object, tactics
                ),
                format!(
                    "{} tactiques MITRE distinctes sur 7j ({}) ≥ seuil {}",
                    tactics,
                    obj.tactics_7d.join(", "),
                    cfg.min_tactics
                ),
            ),
        };

        let incident_id = match store
            .create_incident(
                &obj.object,
                &title,
                severity,
                &[],
                &[],
                obj.n_events_24h as i32,
            )
            .await
        {
            Ok(id) if id > 0 => id,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!("RBA: create_incident failed for {}: {e}", obj.object);
                continue;
            }
        };

        // Attach the RBA "story" so the dashboard + L2 see how the risk built up.
        let story = serde_json::json!({
            "rba": {
                "trigger": match &trigger {
                    RirTrigger::ScoreThreshold { .. } => "score_threshold",
                    RirTrigger::TacticDiversity { .. } => "tactic_diversity",
                },
                "reason": reason,
                "score_24h": obj.score_24h,
                "events_24h": obj.n_events_24h,
                "rules_24h": obj.rules_24h,
                "tactics_7d": obj.tactics_7d,
            }
        });
        if let Err(e) = store.set_incident_enrichment(incident_id, &story).await {
            tracing::warn!("RBA: set_incident_enrichment failed for #{incident_id}: {e}");
        }

        // Bank the contributing events into this notable so they can never fund a
        // second one (the re-fire loop). New events accumulate fresh from here.
        match store
            .mark_risk_events_consumed(&obj.event_ids, incident_id)
            .await
        {
            Ok(n) => tracing::debug!("RBA: consumed {n} risk events into #{incident_id}"),
            Err(e) => tracing::warn!(
                "RBA: mark_risk_events_consumed failed for #{incident_id} ({} events): {e}",
                obj.event_ids.len()
            ),
        }

        tracing::info!(
            "RBA: risk notable #{} created for {} — {} ({})",
            incident_id,
            obj.object,
            severity,
            reason
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(object: &str, score: i32, rule: &str, tactic: Option<&str>, age_hours: i64) -> RiskEvent {
        // created_at = now - age_hours, RFC3339. Tests pass `now` explicitly to
        // aggregate_by_object, but parse_ts needs a fixed reference; we anchor on
        // a fixed epoch so the 24h boundary is deterministic.
        let base = DateTime::parse_from_rfc3339("2026-06-21T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let ts = base - Duration::hours(age_hours);
        RiskEvent {
            id: 0,
            risk_object: object.into(),
            object_type: "asset".into(),
            score,
            source_rule: rule.into(),
            mitre_tactic: tactic.map(String::from),
            mitre_technique: None,
            log_id: None,
            message: None,
            created_at: ts.to_rfc3339(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-21T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn score_sum_only_counts_24h_window() {
        let events = vec![
            ev("host-a", 50, "r1", Some("execution"), 1),   // in 24h
            ev("host-a", 60, "r2", Some("persistence"), 2), // in 24h
            ev("host-a", 90, "r3", Some("exfil"), 100),     // 4d ago → NOT in 24h score
        ];
        let objs = aggregate_by_object(&events, now());
        let a = objs.iter().find(|o| o.object == "host-a").unwrap();
        assert_eq!(
            a.score_24h, 110,
            "only the two <24h events count toward score"
        );
        assert_eq!(a.n_events_24h, 2);
        // but all three tactics count over 7d
        assert_eq!(a.distinct_tactics_7d, 3);
    }

    #[test]
    fn rir_score_threshold_fires() {
        let events = vec![
            ev("h", 50, "r1", Some("a"), 1),
            ev("h", 60, "r2", Some("b"), 1),
        ];
        let objs = aggregate_by_object(&events, now());
        let cfg = RbaConfig {
            score_threshold: 100,
            min_tactics: 5,
        };
        assert_eq!(
            evaluate_rirs(&objs[0], &cfg),
            Some(RirTrigger::ScoreThreshold { score: 110 })
        );
    }

    #[test]
    fn rir_tactic_diversity_fires_even_under_score() {
        // Low score (3x5=15) but 3 distinct tactics over 7d → low-and-slow catch.
        let events = vec![
            ev("h", 5, "r1", Some("initial_access"), 50),
            ev("h", 5, "r2", Some("persistence"), 40),
            ev("h", 5, "r3", Some("exfiltration"), 30),
        ];
        let objs = aggregate_by_object(&events, now());
        let cfg = RbaConfig {
            score_threshold: 100, // far above 15
            min_tactics: 3,
        };
        assert_eq!(
            evaluate_rirs(&objs[0], &cfg),
            Some(RirTrigger::TacticDiversity { tactics: 3 })
        );
    }

    #[test]
    fn no_trigger_under_both_thresholds() {
        let events = vec![ev("h", 10, "r1", Some("a"), 1)];
        let objs = aggregate_by_object(&events, now());
        let cfg = RbaConfig {
            score_threshold: 100,
            min_tactics: 3,
        };
        assert_eq!(evaluate_rirs(&objs[0], &cfg), None);
    }

    #[test]
    fn object_collects_all_contributing_event_ids() {
        // Re-fire fix: the consumer must learn EVERY event that funded an object
        // — the 24h scorers AND the older 7d events — so none survive to re-fire
        // a notable on the next cycle. This is the mechanism that breaks the loop.
        let mut e1 = ev("h", 50, "r1", Some("a"), 1); // <24h
        e1.id = 11;
        let mut e2 = ev("h", 60, "r2", Some("b"), 2); // <24h
        e2.id = 22;
        let mut e3 = ev("h", 5, "r3", Some("c"), 100); // 4d old — outside 24h score
        e3.id = 33;
        let objs = aggregate_by_object(&[e1, e2, e3], now());
        let o = objs.iter().find(|o| o.object == "h").unwrap();
        let mut ids = o.event_ids.clone();
        ids.sort();
        assert_eq!(
            ids,
            vec![11, 22, 33],
            "all contributing events (incl. >24h) must be banked for consumption"
        );
    }

    #[test]
    fn objects_are_isolated() {
        let events = vec![
            ev("host-a", 100, "r1", Some("a"), 1),
            ev("host-b", 10, "r2", Some("b"), 1),
        ];
        let objs = aggregate_by_object(&events, now());
        let cfg = RbaConfig::default();
        let a = objs.iter().find(|o| o.object == "host-a").unwrap();
        let b = objs.iter().find(|o| o.object == "host-b").unwrap();
        assert!(evaluate_rirs(a, &cfg).is_some());
        assert!(evaluate_rirs(b, &cfg).is_none());
    }
}

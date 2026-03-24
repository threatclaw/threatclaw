//! Behavioral Analysis — user/asset baseline + anomaly scoring.
//!
//! Builds a "normal" profile for each user over a 30-day sliding window.
//! Scores each new event against the baseline. High deviation = alert.
//!
//! No ML required — just statistics (mean, stddev, set membership).
//! The baselines generated here serve as future training data for ML (Layer 3).

use crate::db::Database;
use crate::graph::threat_graph::{query, mutate};
use chrono::{Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// A user's behavioral baseline (computed from 30 days of data).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserBaseline {
    pub username: String,
    /// Hours when this user typically logs in (0-23).
    pub usual_hours: Vec<u32>,
    /// Days of week (1=Mon..7=Sun).
    pub usual_days: Vec<u32>,
    /// IP addresses this user typically connects from.
    pub usual_ips: Vec<String>,
    /// Assets this user typically accesses.
    pub usual_assets: Vec<String>,
    /// VLANs this user is typically on.
    pub usual_vlans: Vec<u16>,
    /// Average daily login count.
    pub avg_daily_logins: f64,
    /// Number of days observed (for learning period).
    pub days_observed: u32,
    /// Whether the baseline is mature enough for alerting (>= 7 days).
    pub is_mature: bool,
}

/// A single event to score against the baseline.
#[derive(Debug, Clone)]
pub struct BehaviorEvent {
    pub username: String,
    pub source_ip: String,
    pub target_asset: String,
    pub hour: u32,
    pub weekday: u32,
    pub vlan: Option<u16>,
    pub success: bool,
    pub event_type: String, // "login", "access", "escalation"
}

/// Anomaly scoring result.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyScore {
    pub username: String,
    pub total_score: u8,
    pub level: &'static str,
    pub anomalies: Vec<AnomalyDetail>,
    pub baseline_mature: bool,
}

/// Detail of a single anomaly detected.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyDetail {
    pub category: String,
    pub score: u8,
    pub detail: String,
}

impl AnomalyScore {
    fn level_from_score(score: u8) -> &'static str {
        match score {
            0..=20 => "normal",
            21..=40 => "low",
            41..=60 => "medium",
            61..=80 => "high",
            81..=100 => "critical",
            _ => "critical",
        }
    }
}

/// Score an event against a user's baseline.
/// Returns 0-100: 0=perfectly normal, 100=extremely anomalous.
pub fn score_event(baseline: &UserBaseline, event: &BehaviorEvent) -> AnomalyScore {
    let mut anomalies = vec![];
    let mut total: u16 = 0;

    // Skip scoring if baseline is not mature (learning period)
    if !baseline.is_mature {
        return AnomalyScore {
            username: event.username.clone(),
            total_score: 0,
            level: "learning",
            anomalies: vec![],
            baseline_mature: false,
        };
    }

    // 1. Time anomaly (0-30 points)
    if !baseline.usual_hours.is_empty() && !baseline.usual_hours.contains(&event.hour) {
        let score = if event.hour < 6 || event.hour >= 22 {
            30 // Night time — very suspicious
        } else if event.hour < 8 || event.hour >= 20 {
            15 // Early morning / late evening
        } else {
            8  // Just outside usual hours
        };
        anomalies.push(AnomalyDetail {
            category: "time".into(),
            score,
            detail: format!("Connexion a {}h (habituel: {:?})", event.hour, baseline.usual_hours),
        });
        total += score as u16;
    }

    // 2. Day anomaly (0-20 points)
    if !baseline.usual_days.is_empty() && !baseline.usual_days.contains(&event.weekday) {
        let score = if event.weekday >= 6 { 20 } else { 10 }; // Weekend = more suspicious
        anomalies.push(AnomalyDetail {
            category: "day".into(),
            score,
            detail: format!("Connexion jour {} (habituel: {:?})", event.weekday, baseline.usual_days),
        });
        total += score as u16;
    }

    // 3. Source IP anomaly (0-40 points)
    if !baseline.usual_ips.is_empty() && !baseline.usual_ips.contains(&event.source_ip) {
        let score = if is_external_ip(&event.source_ip) {
            40 // External IP never seen — very suspicious
        } else {
            25 // Internal IP but different from usual
        };
        anomalies.push(AnomalyDetail {
            category: "source_ip".into(),
            score,
            detail: format!("IP {} inconnue (habituel: {:?})", event.source_ip,
                &baseline.usual_ips[..baseline.usual_ips.len().min(3)]),
        });
        total += score as u16;
    }

    // 4. Target asset anomaly (0-30 points)
    if !baseline.usual_assets.is_empty() && !baseline.usual_assets.contains(&event.target_asset) {
        let score = 30;
        anomalies.push(AnomalyDetail {
            category: "target_asset".into(),
            score,
            detail: format!("Acces a '{}' (jamais accede avant)", event.target_asset),
        });
        total += score as u16;
    }

    // 5. VLAN anomaly (0-25 points)
    if let Some(vlan) = event.vlan {
        if !baseline.usual_vlans.is_empty() && !baseline.usual_vlans.contains(&vlan) {
            let score = 25;
            anomalies.push(AnomalyDetail {
                category: "vlan".into(),
                score,
                detail: format!("VLAN {} inhabituel (habituel: {:?})", vlan, baseline.usual_vlans),
            });
            total += score as u16;
        }
    }

    // 6. Failed login (0-10 points — just a signal, not anomaly by itself)
    if !event.success {
        let score = 10;
        anomalies.push(AnomalyDetail {
            category: "failed_login".into(),
            score,
            detail: "Tentative de connexion echouee".into(),
        });
        total += score as u16;
    }

    let final_score = (total as u8).min(100);

    AnomalyScore {
        username: event.username.clone(),
        total_score: final_score,
        level: AnomalyScore::level_from_score(final_score),
        anomalies,
        baseline_mature: true,
    }
}

/// Compute or update a user's baseline from graph history.
pub async fn compute_baseline(store: &dyn Database, username: &str) -> UserBaseline {
    // Get login history for this user from the graph
    let logins = query(store, &format!(
        "MATCH (u:User {{username: '{}'}})-[l:LOGGED_IN]->(a:Asset) \
         RETURN l.source_ip, l.timestamp, a.id, a.hostname \
         ORDER BY l.timestamp DESC LIMIT 500",
        esc(username)
    )).await;

    let mut hours: Vec<u32> = vec![];
    let mut days: Vec<u32> = vec![];
    let mut ips: Vec<String> = vec![];
    let mut assets: Vec<String> = vec![];
    let mut unique_dates = std::collections::HashSet::new();

    for r in &logins {
        // Parse timestamp
        if let Some(ts_str) = r["l.timestamp"].as_str() {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(ts_str) {
                let h = ts.hour();
                let d = ts.weekday().number_from_monday();
                if !hours.contains(&h) { hours.push(h); }
                if !days.contains(&d) { days.push(d); }
                unique_dates.insert(ts.format("%Y-%m-%d").to_string());
            }
        }

        // Source IP
        if let Some(ip) = r["l.source_ip"].as_str() {
            if !ips.contains(&ip.to_string()) && ips.len() < 20 {
                ips.push(ip.to_string());
            }
        }

        // Target asset
        let asset = r["a.hostname"].as_str()
            .or(r["a.id"].as_str())
            .unwrap_or("");
        if !asset.is_empty() && !assets.contains(&asset.to_string()) && assets.len() < 30 {
            assets.push(asset.to_string());
        }
    }

    let days_observed = unique_dates.len() as u32;
    let avg_daily = if days_observed > 0 {
        logins.len() as f64 / days_observed as f64
    } else {
        0.0
    };

    hours.sort();
    days.sort();

    let baseline = UserBaseline {
        username: username.to_string(),
        usual_hours: hours,
        usual_days: days,
        usual_ips: ips,
        usual_assets: assets,
        usual_vlans: vec![], // Populated from pfSense connector
        avg_daily_logins: avg_daily,
        days_observed,
        is_mature: days_observed >= 7,
    };

    // Persist baseline on the User node in the graph
    save_baseline(store, &baseline).await;

    baseline
}

/// Save baseline data on the User node.
async fn save_baseline(store: &dyn Database, baseline: &UserBaseline) {
    let hours_json = serde_json::to_string(&baseline.usual_hours).unwrap_or_default();
    let days_json = serde_json::to_string(&baseline.usual_days).unwrap_or_default();
    let ips_json = serde_json::to_string(&baseline.usual_ips).unwrap_or_default();
    let assets_json = serde_json::to_string(&baseline.usual_assets).unwrap_or_default();

    let cypher = format!(
        "MATCH (u:User {{username: '{}'}}) \
         SET u.baseline_hours = '{}', u.baseline_days = '{}', \
         u.baseline_ips = '{}', u.baseline_assets = '{}', \
         u.baseline_avg_logins = {}, u.baseline_days_observed = {}, \
         u.baseline_updated = '{}' \
         RETURN u",
        esc(&baseline.username),
        esc(&hours_json), esc(&days_json),
        esc(&ips_json), esc(&assets_json),
        baseline.avg_daily_logins, baseline.days_observed,
        Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Load a previously computed baseline from the graph.
pub async fn load_baseline(store: &dyn Database, username: &str) -> Option<UserBaseline> {
    let results = query(store, &format!(
        "MATCH (u:User {{username: '{}'}}) \
         RETURN u.baseline_hours, u.baseline_days, u.baseline_ips, \
         u.baseline_assets, u.baseline_avg_logins, u.baseline_days_observed",
        esc(username)
    )).await;

    let r = results.first()?;

    let hours: Vec<u32> = r["u.baseline_hours"].as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let days: Vec<u32> = r["u.baseline_days"].as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let ips: Vec<String> = r["u.baseline_ips"].as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let assets: Vec<String> = r["u.baseline_assets"].as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let avg_logins = r["u.baseline_avg_logins"].as_f64().unwrap_or(0.0);
    let days_observed = r["u.baseline_days_observed"].as_i64().unwrap_or(0) as u32;

    Some(UserBaseline {
        username: username.to_string(),
        usual_hours: hours,
        usual_days: days,
        usual_ips: ips,
        usual_assets: assets,
        usual_vlans: vec![],
        avg_daily_logins: avg_logins,
        days_observed,
        is_mature: days_observed >= 7,
    })
}

/// Score a login event for a user. Computes baseline if not cached.
pub async fn score_login(
    store: &dyn Database,
    username: &str,
    source_ip: &str,
    target_asset: &str,
    success: bool,
) -> AnomalyScore {
    // Load or compute baseline
    let baseline = match load_baseline(store, username).await {
        Some(b) => b,
        None => compute_baseline(store, username).await,
    };

    let now = Utc::now();
    let event = BehaviorEvent {
        username: username.to_string(),
        source_ip: source_ip.to_string(),
        target_asset: target_asset.to_string(),
        hour: now.hour(),
        weekday: now.weekday().number_from_monday(),
        vlan: None,
        success,
        event_type: "login".into(),
    };

    let score = score_event(&baseline, &event);

    if score.total_score >= 50 {
        tracing::warn!(
            "BEHAVIOR: {} anomaly score {}/100 ({}) — {} anomalies detected",
            username, score.total_score, score.level, score.anomalies.len()
        );
    }

    score
}

/// Update baselines for all active users (call periodically, e.g., daily).
pub async fn refresh_all_baselines(store: &dyn Database) {
    let users = query(store, "MATCH (u:User) RETURN u.username LIMIT 200").await;
    let mut updated = 0;

    for r in &users {
        if let Some(username) = r["u.username"].as_str() {
            compute_baseline(store, username).await;
            updated += 1;
        }
    }

    if updated > 0 {
        tracing::info!("BEHAVIOR: Refreshed baselines for {} users", updated);
    }
}

fn is_external_ip(ip: &str) -> bool {
    !ip.starts_with("10.")
        && !ip.starts_with("192.168.")
        && !ip.starts_with("172.16.")
        && !ip.starts_with("172.17.")
        && !ip.starts_with("172.18.")
        && !ip.starts_with("127.")
        && ip != "::1"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_baseline() -> UserBaseline {
        UserBaseline {
            username: "michel".into(),
            usual_hours: vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
            usual_days: vec![1, 2, 3, 4, 5],
            usual_ips: vec!["192.168.30.15".into()],
            usual_assets: vec!["srv-erp".into(), "srv-files".into()],
            usual_vlans: vec![30],
            avg_daily_logins: 5.0,
            days_observed: 30,
            is_mature: true,
        }
    }

    #[test]
    fn test_normal_behavior() {
        let b = make_baseline();
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "192.168.30.15".into(),
            target_asset: "srv-erp".into(),
            hour: 10, weekday: 3, vlan: Some(30),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 0);
        assert_eq!(score.level, "normal");
    }

    #[test]
    fn test_night_login() {
        let b = make_baseline();
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "192.168.30.15".into(),
            target_asset: "srv-erp".into(),
            hour: 3, weekday: 3, vlan: Some(30),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 30);
        assert_eq!(score.level, "low"); // 21-40 = low
        assert_eq!(score.anomalies.len(), 1);
        assert_eq!(score.anomalies[0].category, "time");
    }

    #[test]
    fn test_unknown_ip() {
        let b = make_baseline();
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "10.0.0.99".into(),
            target_asset: "srv-erp".into(),
            hour: 10, weekday: 3, vlan: Some(30),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 25); // Internal IP but unknown
    }

    #[test]
    fn test_external_ip() {
        let b = make_baseline();
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "185.220.101.42".into(),
            target_asset: "srv-erp".into(),
            hour: 10, weekday: 3, vlan: Some(30),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 40); // External IP = very suspicious
    }

    #[test]
    fn test_unknown_asset() {
        let b = make_baseline();
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "192.168.30.15".into(),
            target_asset: "srv-backup".into(),
            hour: 10, weekday: 3, vlan: Some(30),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 30);
        assert_eq!(score.anomalies[0].category, "target_asset");
    }

    #[test]
    fn test_weekend_login() {
        let b = make_baseline();
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "192.168.30.15".into(),
            target_asset: "srv-erp".into(),
            hour: 10, weekday: 6, vlan: Some(30),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 20); // Saturday
    }

    #[test]
    fn test_kill_chain_combo() {
        let b = make_baseline();
        // Night + external IP + unknown asset + wrong VLAN + weekend
        let event = BehaviorEvent {
            username: "michel".into(),
            source_ip: "185.220.101.42".into(),
            target_asset: "srv-ad".into(),
            hour: 3, weekday: 7, vlan: Some(20),
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert!(score.total_score >= 80); // Should be critical
        assert_eq!(score.level, "critical");
        assert!(score.anomalies.len() >= 4);
    }

    #[test]
    fn test_immature_baseline_no_alert() {
        let b = UserBaseline {
            username: "new_user".into(),
            days_observed: 3,
            is_mature: false,
            ..Default::default()
        };
        let event = BehaviorEvent {
            username: "new_user".into(),
            source_ip: "1.2.3.4".into(),
            target_asset: "srv-secret".into(),
            hour: 3, weekday: 7, vlan: None,
            success: true, event_type: "login".into(),
        };
        let score = score_event(&b, &event);
        assert_eq!(score.total_score, 0); // Learning period — no alerts
        assert_eq!(score.level, "learning");
    }

    #[test]
    fn test_is_external_ip() {
        assert!(!is_external_ip("192.168.1.10"));
        assert!(!is_external_ip("10.0.0.1"));
        assert!(!is_external_ip("127.0.0.1"));
        assert!(is_external_ip("185.220.101.42"));
        assert!(is_external_ip("8.8.8.8"));
    }
}

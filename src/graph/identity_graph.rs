//! Identity Graph — STIX Identity + User Behavior Analytics (UBA).
//!
//! Tracks users, accounts, and groups as graph nodes.
//! Detects anomalous login patterns by analyzing edges:
//! - User logs in from unusual IP
//! - User accesses unusual asset
//! - Admin account used at unusual hours
//! - Account used from multiple countries

use crate::db::Database;
use crate::graph::threat_graph::{mutate, query};
use serde::Serialize;
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// A user identity in the graph.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityNode {
    pub username: String,
    pub is_admin: bool,
    pub is_service_account: bool,
    pub department: Option<String>,
    pub usual_ips: Vec<String>,
    pub usual_assets: Vec<String>,
}

/// A detected identity anomaly.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityAnomaly {
    pub anomaly_type: String,
    pub username: String,
    pub detail: String,
    pub severity: String,
    pub confidence: u8,
}

/// Summary of a user for the /users list view.
#[derive(Debug, Clone, Serialize)]
pub struct UserSummary {
    pub username: String,
    pub is_admin: bool,
    pub is_service_account: bool,
    pub department: Option<String>,
    pub last_seen: Option<String>,
    pub login_count: i64,
    pub failed_login_count: i64,
    pub linked_assets: i64,
}

/// A single login event for the user detail view.
#[derive(Debug, Clone, Serialize)]
pub struct LoginEvent {
    pub asset_id: String,
    pub asset_hostname: Option<String>,
    pub source_ip: String,
    pub protocol: String,
    pub success: bool,
    pub timestamp: String,
}

/// An asset the user has logged into at least once.
#[derive(Debug, Clone, Serialize)]
pub struct LinkedAsset {
    pub asset_id: String,
    pub hostname: Option<String>,
    pub criticality: Option<String>,
    pub login_count: i64,
    pub failed_login_count: i64,
    pub last_login: Option<String>,
}

/// Escalation edge (in/out of a user).
#[derive(Debug, Clone, Serialize)]
pub struct EscalationEdge {
    pub from_user: String,
    pub to_user: String,
    pub method: String,
    pub asset: String,
    pub timestamp: String,
}

/// Full detail for a single user.
#[derive(Debug, Clone, Serialize)]
pub struct UserDetail {
    pub summary: UserSummary,
    pub linked_assets: Vec<LinkedAsset>,
    pub recent_logins: Vec<LoginEvent>,
    pub anomalies: Vec<IdentityAnomaly>,
    pub escalations_out: Vec<EscalationEdge>,
    pub escalations_in: Vec<EscalationEdge>,
}

/// Identity analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityAnalysis {
    pub anomalies: Vec<IdentityAnomaly>,
    pub users_tracked: usize,
    pub summary: String,
}

/// Upsert a User node (STIX Identity).
pub async fn upsert_user(
    store: &dyn Database,
    username: &str,
    is_admin: bool,
    is_service: bool,
    department: Option<&str>,
) {
    let dept = department.unwrap_or("");
    let cypher = format!(
        "MERGE (u:User {{username: '{}'}}) \
         SET u.is_admin = {}, u.is_service_account = {}, u.department = '{}', \
         u.last_seen = '{}' RETURN u",
        esc(username),
        is_admin,
        is_service,
        esc(dept),
        chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Record a login event: User -[:LOGGED_IN]-> Asset
pub async fn record_login(
    store: &dyn Database,
    username: &str,
    asset_id: &str,
    source_ip: &str,
    auth_protocol: &str,
    success: bool,
) {
    // Ensure user exists
    upsert_user(store, username, false, false, None).await;

    let cypher = format!(
        "MATCH (u:User {{username: '{}'}}), (a:Asset {{id: '{}'}}) \
         CREATE (u)-[:LOGGED_IN {{source_ip: '{}', protocol: '{}', success: {}, \
         timestamp: '{}'}}]->(a)",
        esc(username),
        esc(asset_id),
        esc(source_ip),
        esc(auth_protocol),
        success,
        chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Record privilege escalation: User -[:ESCALATED]-> User
pub async fn record_escalation(
    store: &dyn Database,
    from_user: &str,
    to_user: &str,
    method: &str,
    asset_id: &str,
) {
    let cypher = format!(
        "MATCH (u1:User {{username: '{}'}}), (u2:User {{username: '{}'}}) \
         CREATE (u1)-[:ESCALATED {{method: '{}', asset: '{}', timestamp: '{}'}}]->(u2)",
        esc(from_user),
        esc(to_user),
        esc(method),
        esc(asset_id),
        chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Detect identity anomalies from the graph.
pub async fn detect_identity_anomalies(store: &dyn Database) -> IdentityAnalysis {
    let mut anomalies = vec![];

    // 1. Users logging into many different assets (potential compromise/recon)
    let fan_out = detect_user_fan_out(store, 4).await;
    anomalies.extend(fan_out);

    // 2. Failed login clusters (brute force on specific accounts)
    let failed = detect_failed_login_clusters(store).await;
    anomalies.extend(failed);

    // 3. Privilege escalation chains
    let escalations = detect_escalation_chains(store).await;
    anomalies.extend(escalations);

    let users_tracked = count_users(store).await;
    let summary = if anomalies.is_empty() {
        "Aucune anomalie d'identité détectée".into()
    } else {
        format!(
            "{} anomalie(s) d'identité détectée(s) sur {} utilisateurs",
            anomalies.len(),
            users_tracked
        )
    };

    IdentityAnalysis {
        anomalies,
        users_tracked,
        summary,
    }
}

/// Users logging into 4+ different assets — potential lateral movement or compromised account.
async fn detect_user_fan_out(store: &dyn Database, threshold: i64) -> Vec<IdentityAnomaly> {
    let results = query(
        store,
        &format!(
            "MATCH (u:User)-[:LOGGED_IN]->(a:Asset) \
         WITH u, count(DISTINCT a) AS asset_count, collect(DISTINCT a.hostname) AS assets \
         WHERE asset_count >= {} \
         RETURN u.username, u.is_admin, asset_count, assets \
         ORDER BY asset_count DESC LIMIT 10",
            threshold
        ),
    )
    .await;

    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let username = result["u.username"].as_str()?;
            let count = result["asset_count"].as_i64().unwrap_or(0);
            let is_admin = result["u.is_admin"].as_bool().unwrap_or(false);

            Some(IdentityAnomaly {
                anomaly_type: "user_fan_out".into(),
                username: username.to_string(),
                detail: format!("{} accède à {} assets différents", username, count),
                severity: if is_admin {
                    "high".into()
                } else {
                    "medium".into()
                },
                confidence: (50 + (count as u8).min(40)).min(100),
            })
        })
        .collect()
}

/// Users with many failed logins — brute force target.
async fn detect_failed_login_clusters(store: &dyn Database) -> Vec<IdentityAnomaly> {
    let results = query(
        store,
        "MATCH (u:User)-[l:LOGGED_IN]->(a:Asset) \
         WHERE l.success = false \
         WITH u, count(l) AS fails, collect(DISTINCT a.hostname) AS targets \
         WHERE fails >= 5 \
         RETURN u.username, fails, targets \
         ORDER BY fails DESC LIMIT 10",
    )
    .await;

    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let username = result["u.username"].as_str()?;
            let fails = result["fails"].as_i64().unwrap_or(0);

            Some(IdentityAnomaly {
                anomaly_type: "failed_login_cluster".into(),
                username: username.to_string(),
                detail: format!("{} : {} tentatives de connexion échouées", username, fails),
                severity: if fails >= 20 {
                    "critical".into()
                } else {
                    "high".into()
                },
                confidence: (40 + (fails as u8).min(50)).min(100),
            })
        })
        .collect()
}

/// Detect privilege escalation chains.
async fn detect_escalation_chains(store: &dyn Database) -> Vec<IdentityAnomaly> {
    let results = query(
        store,
        "MATCH (u1:User)-[e:ESCALATED]->(u2:User) \
         WHERE u2.is_admin = true \
         RETURN u1.username, u2.username, e.method, e.asset \
         LIMIT 10",
    )
    .await;

    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let from = result["u1.username"].as_str()?;
            let to = result["u2.username"].as_str()?;
            let method = result["e.method"].as_str().unwrap_or("unknown");

            Some(IdentityAnomaly {
                anomaly_type: "privilege_escalation".into(),
                username: from.to_string(),
                detail: format!("{} → {} via {} (escalade vers admin)", from, to, method),
                severity: "critical".into(),
                confidence: 85,
            })
        })
        .collect()
}

async fn count_users(store: &dyn Database) -> usize {
    let results = query(store, "MATCH (u:User) RETURN count(u)").await;
    results
        .first()
        .and_then(|r| r["count(u)"].as_i64())
        .unwrap_or(0) as usize
}

/// List all users with aggregated stats for the /users overview page.
pub async fn list_users(store: &dyn Database, limit: u64) -> Vec<UserSummary> {
    let rows = query(
        store,
        &format!(
            "MATCH (u:User) \
             OPTIONAL MATCH (u)-[l:LOGGED_IN]->(:Asset) \
             WITH u, count(l) AS total_logins, \
                  sum(CASE WHEN l.success = false THEN 1 ELSE 0 END) AS failed_logins \
             OPTIONAL MATCH (u)-[:LOGGED_IN]->(a:Asset) \
             WITH u, total_logins, failed_logins, count(DISTINCT a) AS asset_count \
             RETURN u.username, u.is_admin, u.is_service_account, u.department, u.last_seen, \
                    total_logins, failed_logins, asset_count \
             ORDER BY total_logins DESC, u.username ASC LIMIT {limit}"
        ),
    )
    .await;

    rows.into_iter()
        .filter_map(|r| {
            let username = r["u.username"].as_str()?.to_string();
            let dept = r["u.department"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from);
            Some(UserSummary {
                username,
                is_admin: r["u.is_admin"].as_bool().unwrap_or(false),
                is_service_account: r["u.is_service_account"].as_bool().unwrap_or(false),
                department: dept,
                last_seen: r["u.last_seen"].as_str().map(String::from),
                login_count: r["total_logins"].as_i64().unwrap_or(0),
                failed_login_count: r["failed_logins"].as_i64().unwrap_or(0),
                linked_assets: r["asset_count"].as_i64().unwrap_or(0),
            })
        })
        .collect()
}

/// Detailed view of a single user: profile, linked assets, recent logins,
/// escalations both directions, anomalies.
pub async fn get_user_detail(store: &dyn Database, username: &str) -> Option<UserDetail> {
    let u = esc(username);

    // Profile + aggregated counts
    let profile_rows = query(
        store,
        &format!(
            "MATCH (u:User {{username: '{u}'}}) \
             OPTIONAL MATCH (u)-[l:LOGGED_IN]->(:Asset) \
             WITH u, count(l) AS total_logins, \
                  sum(CASE WHEN l.success = false THEN 1 ELSE 0 END) AS failed_logins \
             OPTIONAL MATCH (u)-[:LOGGED_IN]->(a:Asset) \
             WITH u, total_logins, failed_logins, count(DISTINCT a) AS asset_count \
             RETURN u.username, u.is_admin, u.is_service_account, u.department, u.last_seen, \
                    total_logins, failed_logins, asset_count LIMIT 1"
        ),
    )
    .await;
    let r = profile_rows.into_iter().next()?;
    let uname = r["u.username"].as_str()?.to_string();
    let summary = UserSummary {
        username: uname.clone(),
        is_admin: r["u.is_admin"].as_bool().unwrap_or(false),
        is_service_account: r["u.is_service_account"].as_bool().unwrap_or(false),
        department: r["u.department"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from),
        last_seen: r["u.last_seen"].as_str().map(String::from),
        login_count: r["total_logins"].as_i64().unwrap_or(0),
        failed_login_count: r["failed_logins"].as_i64().unwrap_or(0),
        linked_assets: r["asset_count"].as_i64().unwrap_or(0),
    };

    // Linked assets with per-asset login stats
    let asset_rows = query(
        store,
        &format!(
            "MATCH (u:User {{username: '{u}'}})-[l:LOGGED_IN]->(a:Asset) \
             WITH a, count(l) AS logins, \
                  sum(CASE WHEN l.success = false THEN 1 ELSE 0 END) AS fails, \
                  max(l.timestamp) AS last_login \
             RETURN a.id, a.hostname, a.criticality, logins, fails, last_login \
             ORDER BY logins DESC LIMIT 50"
        ),
    )
    .await;
    let linked_assets: Vec<LinkedAsset> = asset_rows
        .into_iter()
        .filter_map(|r| {
            let asset_id = r["a.id"].as_str()?.to_string();
            Some(LinkedAsset {
                asset_id,
                hostname: r["a.hostname"].as_str().map(String::from),
                criticality: r["a.criticality"].as_str().map(String::from),
                login_count: r["logins"].as_i64().unwrap_or(0),
                failed_login_count: r["fails"].as_i64().unwrap_or(0),
                last_login: r["last_login"].as_str().map(String::from),
            })
        })
        .collect();

    // Recent login events
    let login_rows = query(
        store,
        &format!(
            "MATCH (u:User {{username: '{u}'}})-[l:LOGGED_IN]->(a:Asset) \
             RETURN a.id, a.hostname, l.source_ip, l.protocol, l.success, l.timestamp \
             ORDER BY l.timestamp DESC LIMIT 100"
        ),
    )
    .await;
    let recent_logins: Vec<LoginEvent> = login_rows
        .into_iter()
        .filter_map(|r| {
            let asset_id = r["a.id"].as_str()?.to_string();
            Some(LoginEvent {
                asset_id,
                asset_hostname: r["a.hostname"].as_str().map(String::from),
                source_ip: r["l.source_ip"].as_str().unwrap_or("").to_string(),
                protocol: r["l.protocol"].as_str().unwrap_or("").to_string(),
                success: r["l.success"].as_bool().unwrap_or(false),
                timestamp: r["l.timestamp"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    // Escalations out (user → someone)
    let esc_out_rows = query(
        store,
        &format!(
            "MATCH (u:User {{username: '{u}'}})-[e:ESCALATED]->(t:User) \
             RETURN u.username, t.username, e.method, e.asset, e.timestamp \
             ORDER BY e.timestamp DESC LIMIT 50"
        ),
    )
    .await;
    let escalations_out: Vec<EscalationEdge> = esc_out_rows
        .into_iter()
        .filter_map(|r| {
            Some(EscalationEdge {
                from_user: r["u.username"].as_str()?.to_string(),
                to_user: r["t.username"].as_str()?.to_string(),
                method: r["e.method"].as_str().unwrap_or("").to_string(),
                asset: r["e.asset"].as_str().unwrap_or("").to_string(),
                timestamp: r["e.timestamp"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    // Escalations in (someone → user)
    let esc_in_rows = query(
        store,
        &format!(
            "MATCH (s:User)-[e:ESCALATED]->(u:User {{username: '{u}'}}) \
             RETURN s.username, u.username, e.method, e.asset, e.timestamp \
             ORDER BY e.timestamp DESC LIMIT 50"
        ),
    )
    .await;
    let escalations_in: Vec<EscalationEdge> = esc_in_rows
        .into_iter()
        .filter_map(|r| {
            Some(EscalationEdge {
                from_user: r["s.username"].as_str()?.to_string(),
                to_user: r["u.username"].as_str()?.to_string(),
                method: r["e.method"].as_str().unwrap_or("").to_string(),
                asset: r["e.asset"].as_str().unwrap_or("").to_string(),
                timestamp: r["e.timestamp"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    // Anomalies filtered for this user
    let all_anomalies = detect_identity_anomalies(store).await;
    let anomalies: Vec<IdentityAnomaly> = all_anomalies
        .anomalies
        .into_iter()
        .filter(|a| a.username == uname)
        .collect();

    Some(UserDetail {
        summary,
        linked_assets,
        recent_logins,
        anomalies,
        escalations_out,
        escalations_in,
    })
}

/// Sync users from auth logs into the identity graph.
pub async fn sync_users_from_logs(store: &dyn Database) {
    use crate::db::threatclaw_store::ThreatClawStore;

    let logs = store
        .query_logs(1440, None, Some("auth"), 200)
        .await
        .unwrap_or_default();
    let mut synced = 0;

    for log in &logs {
        let msg = log
            .data
            .as_str()
            .map(|s| s.to_lowercase())
            .or_else(|| log.data["message"].as_str().map(|s| s.to_lowercase()))
            .unwrap_or_default();
        // Extract username from common auth log patterns
        if let Some(username) = extract_username_from_log(&msg) {
            let is_admin = msg.contains("root") || msg.contains("admin") || msg.contains("sudo");
            upsert_user(store, &username, is_admin, false, None).await;
            synced += 1;
        }
    }

    if synced > 0 {
        tracing::info!("IDENTITY: Synced {} users from auth logs", synced);
    }
}

/// Extract username from common log formats.
fn extract_username_from_log(msg: &str) -> Option<String> {
    // Pattern: "for user xxx" or "user=xxx" or "by xxx"
    let patterns = [
        ("for user ", " "),
        ("user=", " "),
        ("for ", " from"),
        ("session opened for user ", " "),
        ("accepted password for ", " "),
        ("accepted publickey for ", " "),
    ];

    for (prefix, suffix) in patterns {
        if let Some(start) = msg.find(prefix) {
            let rest = &msg[start + prefix.len()..];
            let end = rest.find(suffix).unwrap_or(rest.len());
            let username = rest[..end].trim();
            if !username.is_empty() && username.len() < 64 {
                return Some(username.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_username() {
        assert_eq!(
            extract_username_from_log("accepted password for jean from 192.168.1.1"),
            Some("jean".into())
        );
        assert_eq!(
            extract_username_from_log("session opened for user admin by uid=0"),
            Some("admin".into())
        );
        assert_eq!(
            extract_username_from_log("user=root something"),
            Some("root".into())
        );
        assert_eq!(extract_username_from_log("random log message"), None);
    }
}

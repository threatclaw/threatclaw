//! Threat Graph — CRUD operations on the Apache AGE graph.
//!
//! Executes Cypher queries via the ThreatClawStore::execute_cypher method.
//! All data is stored in PostgreSQL alongside relational data.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde_json::json;

/// Execute a Cypher query and return results.
pub async fn query(store: &dyn Database, cypher: &str) -> Vec<serde_json::Value> {
    match store.execute_cypher(cypher).await {
        Ok(results) => results,
        Err(e) => {
            tracing::warn!("GRAPH: Cypher query failed: {e}");
            vec![]
        }
    }
}

/// Execute a Cypher mutation (CREATE/MERGE) — no return value needed.
pub async fn mutate(store: &dyn Database, cypher: &str) -> bool {
    match store.execute_cypher(cypher).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("GRAPH: Cypher mutation failed: {e}");
            false
        }
    }
}

// ══════════════════════════════════════════════════════════
// NODE UPSERTS — Add or update nodes in the graph
// ══════════════════════════════════════════════════════════

/// Upsert an IP node with enrichment data.
pub async fn upsert_ip(store: &dyn Database, addr: &str, country: Option<&str>, asn: Option<&str>, classification: Option<&str>) {
    let esc = |s: &str| s.replace('\'', "\\'");
    let mut sets = vec![format!("ip.addr = '{}'", esc(addr))];
    if let Some(c) = country { sets.push(format!("ip.country = '{}'", esc(c))); }
    if let Some(a) = asn { sets.push(format!("ip.asn = '{}'", esc(a))); }
    if let Some(c) = classification { sets.push(format!("ip.classification = '{}'", esc(c))); }
    sets.push(format!("ip.last_seen = '{}'", chrono::Utc::now().to_rfc3339()));

    let cypher = format!(
        "MERGE (ip:IP {{addr: '{}'}}) SET {} RETURN ip",
        esc(addr), sets.join(", ")
    );
    mutate(store, &cypher).await;
}

/// Upsert an Asset node.
pub async fn upsert_asset(store: &dyn Database, id: &str, hostname: &str, asset_type: &str, criticality: &str) {
    let esc = |s: &str| s.replace('\'', "\\'");
    let cypher = format!(
        "MERGE (a:Asset {{id: '{}'}}) SET a.hostname = '{}', a.type = '{}', a.criticality = '{}', a.last_seen = '{}' RETURN a",
        esc(id), esc(hostname), esc(asset_type), esc(criticality), chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Upsert a CVE node.
pub async fn upsert_cve(store: &dyn Database, cve_id: &str, cvss: f64, epss: f64, in_kev: bool) {
    let esc = |s: &str| s.replace('\'', "\\'");
    let cypher = format!(
        "MERGE (c:CVE {{id: '{}'}}) SET c.cvss = {}, c.epss = {}, c.in_kev = {} RETURN c",
        esc(cve_id), cvss, epss, in_kev
    );
    mutate(store, &cypher).await;
}

/// Upsert a MITRE ATT&CK Technique node.
pub async fn upsert_technique(store: &dyn Database, mitre_id: &str, name: &str, tactic: &str) {
    let esc = |s: &str| s.replace('\'', "\\'");
    let cypher = format!(
        "MERGE (t:Technique {{mitre_id: '{}'}}) SET t.name = '{}', t.tactic = '{}' RETURN t",
        esc(mitre_id), esc(name), esc(tactic)
    );
    mutate(store, &cypher).await;
}

// ══════════════════════════════════════════════════════════
// RELATIONSHIP CREATION — Connect nodes
// ══════════════════════════════════════════════════════════

/// Record an attack: IP → ATTACKS → Asset
pub async fn record_attack(store: &dyn Database, ip_addr: &str, asset_id: &str, method: &str) {
    let esc = |s: &str| s.replace('\'', "\\'");
    let cypher = format!(
        "MATCH (ip:IP {{addr: '{}'}}), (a:Asset {{id: '{}'}}) \
         CREATE (ip)-[:ATTACKS {{method: '{}', timestamp: '{}'}}]->(a)",
        esc(ip_addr), esc(asset_id), esc(method), chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Record CVE affects Asset
pub async fn record_cve_affects(store: &dyn Database, cve_id: &str, asset_id: &str) {
    let esc = |s: &str| s.replace('\'', "\\'");
    let cypher = format!(
        "MATCH (c:CVE {{id: '{}'}}), (a:Asset {{id: '{}'}}) MERGE (c)-[:AFFECTS]->(a)",
        esc(cve_id), esc(asset_id)
    );
    mutate(store, &cypher).await;
}

// ══════════════════════════════════════════════════════════
// INVESTIGATION QUERIES — Power the deterministic pipeline
// ══════════════════════════════════════════════════════════

/// Find all IPs that have attacked a specific asset.
pub async fn find_attackers(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    let esc = |s: &str| s.replace('\'', "\\'");
    query(store, &format!(
        "MATCH (ip:IP)-[att:ATTACKS]->(a:Asset {{id: '{}'}}) \
         RETURN ip.addr, ip.country, ip.classification, att.method",
        esc(asset_id)
    )).await
}

/// Find all CVEs affecting an asset (especially KEV).
pub async fn find_asset_cves(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    let esc = |s: &str| s.replace('\'', "\\'");
    query(store, &format!(
        "MATCH (c:CVE)-[:AFFECTS]->(a:Asset {{id: '{}'}}) RETURN c.id, c.cvss, c.epss, c.in_kev",
        esc(asset_id)
    )).await
}

/// Find all assets attacked by a specific IP.
pub async fn find_ip_targets(store: &dyn Database, ip_addr: &str) -> Vec<serde_json::Value> {
    let esc = |s: &str| s.replace('\'', "\\'");
    query(store, &format!(
        "MATCH (ip:IP {{addr: '{}'}})-[:ATTACKS]->(a:Asset) RETURN a.id, a.hostname, a.criticality",
        esc(ip_addr)
    )).await
}

/// Build full investigation context for an asset (for L2 Reasoning).
pub async fn build_investigation_context(store: &dyn Database, asset_id: &str) -> serde_json::Value {
    let attackers = find_attackers(store, asset_id).await;
    let cves = find_asset_cves(store, asset_id).await;

    json!({
        "asset_id": asset_id,
        "attackers": attackers,
        "cves": cves,
        "graph_context": true,
    })
}

/// Populate the graph from the current findings and alerts in the relational DB.
/// Called by the Intelligence Engine to keep the graph in sync.
pub async fn sync_graph_from_db(store: &dyn Database) {
    // Sync assets from targets
    let targets = store.list_settings("_targets").await.unwrap_or_default();
    for t in &targets {
        let v = &t.value;
        let id = v["id"].as_str().unwrap_or("");
        let host = v["host"].as_str().unwrap_or("");
        let ttype = v["target_type"].as_str().unwrap_or("linux");
        if !id.is_empty() && !host.is_empty() {
            upsert_asset(store, id, host, ttype, "medium").await;
        }
    }

    // Sync IPs from alerts
    let alerts = store.list_alerts(None, None, 100).await.unwrap_or_default();
    for a in &alerts {
        if let Some(ref ip) = a.source_ip {
            let clean_ip = ip.split('/').next().unwrap_or("").trim();
            if !clean_ip.is_empty() && !clean_ip.starts_with("10.") && !clean_ip.starts_with("192.168.") && !clean_ip.starts_with("127.") {
                upsert_ip(store, clean_ip, None, None, None).await;
                // Record attack if we can identify the target
                if let Some(ref hostname) = a.hostname {
                    // Find the target ID from hostname
                    for t in &targets {
                        if t.value["host"].as_str() == Some(hostname) || t.value["id"].as_str() == Some(hostname) {
                            let target_id = t.value["id"].as_str().unwrap_or(hostname);
                            record_attack(store, clean_ip, target_id, &a.title).await;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Sync CVEs from findings
    let findings = store.list_findings(None, Some("open"), None, 200).await.unwrap_or_default();
    for f in &findings {
        if let Some(cve) = f.metadata.as_object().and_then(|m| m.get("cve")).and_then(|v| v.as_str()) {
            let cvss = f.metadata["cvss"].as_f64().unwrap_or(0.0);
            let epss = f.metadata["epss"].as_f64().unwrap_or(0.0);
            let in_kev = f.metadata["exploited_in_wild"].as_bool().unwrap_or(false);
            upsert_cve(store, cve, cvss, epss, in_kev).await;

            // Link CVE to asset
            if let Some(ref asset) = f.asset {
                for t in &targets {
                    if t.value["host"].as_str() == Some(asset) || t.value["id"].as_str() == Some(asset) {
                        let target_id = t.value["id"].as_str().unwrap_or(asset);
                        record_cve_affects(store, cve, target_id).await;
                        break;
                    }
                }
            }
        }
    }

    tracing::info!("GRAPH: Synced from DB — {} targets, {} alerts, {} findings", targets.len(), alerts.len(), findings.len());
}

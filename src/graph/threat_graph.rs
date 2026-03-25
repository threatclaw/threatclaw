//! Threat Graph — CRUD operations on the Apache AGE graph.
//!
//! Executes Cypher queries via the ThreatClawStore::execute_cypher method.
//! All data is stored in PostgreSQL alongside relational data.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde_json::json;

/// Sanitize a value for use inside Cypher string literals.
/// Strips all characters except safe alphanumerics and basic punctuation.
fn sanitize_cypher_value(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || " ._-,:/()+@".contains(*c)).collect()
}

/// Validate that a string looks like an IP address (v4 or v6).
fn validate_ip(ip: &str) -> bool {
    std::net::IpAddr::from_str(ip).is_ok() || ip.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':')
}

/// Validate an identifier (asset IDs, rule IDs, CVE IDs, MITRE IDs).
fn validate_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_alphanumeric() || "-_.".contains(c))
}

use std::str::FromStr;

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
            tracing::warn!("GRAPH: Cypher mutation failed: {e} | query: {}", &cypher[..cypher.len().min(120)]);
            false
        }
    }
}

// ══════════════════════════════════════════════════════════
// NODE UPSERTS — Add or update nodes in the graph
// ══════════════════════════════════════════════════════════

/// Upsert an IP node with enrichment data.
pub async fn upsert_ip(store: &dyn Database, addr: &str, country: Option<&str>, asn: Option<&str>, classification: Option<&str>) {
    if !validate_ip(addr) {
        tracing::warn!("GRAPH: Invalid IP address, skipping upsert: {}", &addr[..addr.len().min(40)]);
        return;
    }
    let safe_addr = sanitize_cypher_value(addr);
    let mut sets = vec![format!("ip.addr = '{}'", safe_addr)];
    if let Some(c) = country { sets.push(format!("ip.country = '{}'", sanitize_cypher_value(c))); }
    if let Some(a) = asn { sets.push(format!("ip.asn = '{}'", sanitize_cypher_value(a))); }
    if let Some(c) = classification { sets.push(format!("ip.classification = '{}'", sanitize_cypher_value(c))); }
    sets.push(format!("ip.last_seen = '{}'", chrono::Utc::now().to_rfc3339()));

    let cypher = format!(
        "MERGE (ip:IP {{addr: '{}'}}) SET {} RETURN ip",
        safe_addr, sets.join(", ")
    );
    mutate(store, &cypher).await;
}

/// Upsert an Asset node.
pub async fn upsert_asset(store: &dyn Database, id: &str, hostname: &str, asset_type: &str, criticality: &str) {
    if !validate_id(id) {
        tracing::warn!("GRAPH: Invalid asset ID, skipping upsert: {}", &id[..id.len().min(40)]);
        return;
    }
    let cypher = format!(
        "MERGE (a:Asset {{id: '{}'}}) SET a.hostname = '{}', a.type = '{}', a.criticality = '{}', a.last_seen = '{}' RETURN a",
        sanitize_cypher_value(id), sanitize_cypher_value(hostname), sanitize_cypher_value(asset_type), sanitize_cypher_value(criticality), chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Upsert a CVE node.
pub async fn upsert_cve(store: &dyn Database, cve_id: &str, cvss: f64, epss: f64, in_kev: bool) {
    if !validate_id(cve_id) {
        tracing::warn!("GRAPH: Invalid CVE ID, skipping upsert: {}", &cve_id[..cve_id.len().min(40)]);
        return;
    }
    let cypher = format!(
        "MERGE (c:CVE {{id: '{}'}}) SET c.cvss = {}, c.epss = {}, c.in_kev = {} RETURN c",
        sanitize_cypher_value(cve_id), cvss, epss, in_kev
    );
    mutate(store, &cypher).await;
}

/// Upsert a MITRE ATT&CK Technique node.
pub async fn upsert_technique(store: &dyn Database, mitre_id: &str, name: &str, tactic: &str) {
    if !validate_id(mitre_id) {
        tracing::warn!("GRAPH: Invalid MITRE ID, skipping upsert: {}", &mitre_id[..mitre_id.len().min(40)]);
        return;
    }
    let cypher = format!(
        "MERGE (t:Technique {{mitre_id: '{}'}}) SET t.name = '{}', t.tactic = '{}' RETURN t",
        sanitize_cypher_value(mitre_id), sanitize_cypher_value(name), sanitize_cypher_value(tactic)
    );
    mutate(store, &cypher).await;
}

// ══════════════════════════════════════════════════════════
// RELATIONSHIP CREATION — Connect nodes
// ══════════════════════════════════════════════════════════

/// Record an attack: IP → ATTACKS → Asset
pub async fn record_attack(store: &dyn Database, ip_addr: &str, asset_id: &str, method: &str) {
    if !validate_ip(ip_addr) || !validate_id(asset_id) {
        tracing::warn!("GRAPH: Invalid IP or asset ID in record_attack, skipping");
        return;
    }
    let cypher = format!(
        "MATCH (ip:IP {{addr: '{}'}}), (a:Asset {{id: '{}'}}) \
         CREATE (ip)-[:ATTACKS {{method: '{}', timestamp: '{}'}}]->(a)",
        sanitize_cypher_value(ip_addr), sanitize_cypher_value(asset_id), sanitize_cypher_value(method), chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Record CVE affects Asset
pub async fn record_cve_affects(store: &dyn Database, cve_id: &str, asset_id: &str) {
    if !validate_id(cve_id) || !validate_id(asset_id) {
        tracing::warn!("GRAPH: Invalid CVE or asset ID in record_cve_affects, skipping");
        return;
    }
    let cypher = format!(
        "MATCH (c:CVE {{id: '{}'}}), (a:Asset {{id: '{}'}}) MERGE (c)-[:AFFECTS]->(a)",
        sanitize_cypher_value(cve_id), sanitize_cypher_value(asset_id)
    );
    mutate(store, &cypher).await;
}

// ══════════════════════════════════════════════════════════
// INVESTIGATION QUERIES — Power the deterministic pipeline
// ══════════════════════════════════════════════════════════

/// Find all IPs that have attacked a specific asset.
pub async fn find_attackers(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    if !validate_id(asset_id) { return vec![]; }
    query(store, &format!(
        "MATCH (ip:IP)-[att:ATTACKS]->(a:Asset {{id: '{}'}}) \
         RETURN ip.addr, ip.country, ip.classification, att.method",
        sanitize_cypher_value(asset_id)
    )).await
}

/// Find all CVEs affecting an asset (especially KEV).
pub async fn find_asset_cves(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    if !validate_id(asset_id) { return vec![]; }
    query(store, &format!(
        "MATCH (c:CVE)-[:AFFECTS]->(a:Asset {{id: '{}'}}) RETURN c.id, c.cvss, c.epss, c.in_kev",
        sanitize_cypher_value(asset_id)
    )).await
}

/// Find all assets attacked by a specific IP.
pub async fn find_ip_targets(store: &dyn Database, ip_addr: &str) -> Vec<serde_json::Value> {
    if !validate_ip(ip_addr) { return vec![]; }
    query(store, &format!(
        "MATCH (ip:IP {{addr: '{}'}})-[:ATTACKS]->(a:Asset) RETURN a.id, a.hostname, a.criticality",
        sanitize_cypher_value(ip_addr)
    )).await
}

/// Build full investigation context for an asset (for L2 Reasoning).
/// Includes attackers, CVEs, and analyst notes from the graph.
pub async fn build_investigation_context(store: &dyn Database, asset_id: &str) -> serde_json::Value {
    let attackers = find_attackers(store, asset_id).await;
    let cves = find_asset_cves(store, asset_id).await;
    let notes = crate::graph::notes::find_notes_for_asset(store, asset_id).await;

    json!({
        "asset_id": asset_id,
        "attackers": attackers,
        "cves": cves,
        "analyst_notes": notes,
        "graph_context": true,
    })
}

/// Populate the graph from the current findings, alerts, and assets in the relational DB.
/// Called by the Intelligence Engine to keep the graph in sync.
/// Now uses the new `assets` table + IP classifier for proper correlation.
pub async fn sync_graph_from_db(store: &dyn Database) {
    use crate::db::threatclaw_store::ThreatClawStore;
    use crate::agent::ip_classifier;

    // ── Load assets from the new assets table ──
    let assets = store.list_assets(None, Some("active"), 500).await.unwrap_or_default();
    let mut asset_ip_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for a in &assets {
        upsert_asset(store, &a.id, &a.name, &a.category, &a.criticality).await;
        for ip in &a.ip_addresses {
            asset_ip_map.insert(ip.clone(), a.id.clone());
        }
        if let Some(ref hostname) = a.hostname {
            asset_ip_map.insert(hostname.clone(), a.id.clone());
        }
    }

    // ── Also load legacy targets (backward compat) ──
    let targets = store.list_settings("_targets").await.unwrap_or_default();
    for t in &targets {
        let v = &t.value;
        let id = v["id"].as_str().unwrap_or("");
        let host = v["host"].as_str().unwrap_or("");
        let ttype = v["target_type"].as_str().unwrap_or("linux");
        if !id.is_empty() && !host.is_empty() {
            if !asset_ip_map.contains_key(host) {
                upsert_asset(store, id, host, ttype, "medium").await;
                asset_ip_map.insert(host.to_string(), id.to_string());
            }
        }
    }

    // ── Load internal networks for IP classification ──
    let networks_db = store.list_internal_networks().await.unwrap_or_default();
    let networks: Vec<ip_classifier::NetworkRange> = networks_db.iter()
        .filter_map(|n| ip_classifier::NetworkRange::from_cidr(&n.cidr, n.label.as_deref().unwrap_or(""), &n.zone))
        .collect();
    let known_ips: Vec<String> = asset_ip_map.keys().cloned().collect();

    // ── Process alerts — classify IPs and create graph relationships ──
    let alerts = store.list_alerts(None, None, 200).await.unwrap_or_default();
    for a in &alerts {
        if let Some(ref ip) = a.source_ip {
            let clean_ip = ip.split('/').next().unwrap_or("").trim();
            if clean_ip.is_empty() { continue; }

            let classification = ip_classifier::classify(clean_ip, &networks, &known_ips);

            match classification {
                ip_classifier::IpClass::External => {
                    // External IP = attacker → upsert as IP node
                    upsert_ip(store, clean_ip, None, None, Some("suspicious")).await;

                    // Find the target asset (from hostname or dest IP)
                    if let Some(ref hostname) = a.hostname {
                        if let Some(asset_id) = asset_ip_map.get(hostname.as_str())
                            .or_else(|| asset_ip_map.get(hostname)) {
                            record_attack(store, clean_ip, asset_id, &a.title).await;
                        }
                    }
                }
                ip_classifier::IpClass::InternalKnown(ref asset_id) => {
                    // Internal known = this asset is the SOURCE of suspicious activity
                    // (e.g., compromised server doing lateral movement)
                    if let Some(ref hostname) = a.hostname {
                        if let Some(target_id) = asset_ip_map.get(hostname.as_str()) {
                            if target_id != asset_id {
                                // Internal → internal = lateral movement
                                upsert_ip(store, clean_ip, None, None, Some("lateral")).await;
                                record_attack(store, clean_ip, target_id, &format!("lateral: {}", a.title)).await;
                            }
                        }
                    }
                }
                ip_classifier::IpClass::InternalUnknown => {
                    // Unknown device on internal network — auto-create asset
                    let auto_id = format!("auto-{}", clean_ip.replace('.', "-"));
                    if !asset_ip_map.contains_key(clean_ip) {
                        let _ = store.upsert_asset(&crate::db::threatclaw_store::NewAsset {
                            id: auto_id.clone(),
                            name: format!("Unknown {}", clean_ip),
                            category: "unknown".into(),
                            subcategory: None,
                            role: None,
                            criticality: "medium".into(),
                            ip_addresses: vec![clean_ip.to_string()],
                            mac_address: None,
                            hostname: None,
                            fqdn: None,
                            url: None,
                            os: None,
                            mac_vendor: None,
                            source: "alert-auto".into(),
                            owner: None,
                            location: None,
                            tags: vec!["auto-discovered".into()],
                        }).await;
                        upsert_asset(store, &auto_id, clean_ip, "unknown", "medium").await;
                        asset_ip_map.insert(clean_ip.to_string(), auto_id.clone());
                        tracing::info!("GRAPH: Auto-created unknown asset {} for internal IP {}", auto_id, clean_ip);
                    }
                    upsert_ip(store, clean_ip, None, None, Some("unknown-internal")).await;
                }
                ip_classifier::IpClass::Special => {} // ignore loopback, multicast
            }
        }

        // Also process the hostname/dest as an asset target
        if let Some(ref hostname) = a.hostname {
            let host_clean = hostname.trim();
            if !host_clean.is_empty() {
                if let Some(asset_id) = asset_ip_map.get(host_clean) {
                    upsert_asset(store, asset_id, host_clean,
                        &assets.iter().find(|aa| aa.id == *asset_id).map(|aa| aa.category.as_str()).unwrap_or("server"),
                        &assets.iter().find(|aa| aa.id == *asset_id).map(|aa| aa.criticality.as_str()).unwrap_or("medium"),
                    ).await;
                }
            }
        }
    }

    // ── Sync CVEs from findings ──
    let findings = store.list_findings(None, Some("open"), None, 200).await.unwrap_or_default();
    for f in &findings {
        if let Some(cve) = f.metadata.as_object().and_then(|m| m.get("cve")).and_then(|v| v.as_str()) {
            let cvss = f.metadata["cvss"].as_f64().unwrap_or(0.0);
            let epss = f.metadata["epss"].as_f64().unwrap_or(0.0);
            let in_kev = f.metadata["exploited_in_wild"].as_bool().unwrap_or(false);
            upsert_cve(store, cve, cvss, epss, in_kev).await;

            // Link CVE to asset
            if let Some(ref asset_name) = f.asset {
                if let Some(asset_id) = asset_ip_map.get(asset_name.as_str()) {
                    record_cve_affects(store, cve, asset_id).await;
                }
            }
        }
    }

    tracing::info!("GRAPH: Synced from DB — {} assets, {} alerts, {} findings", assets.len() + targets.len(), alerts.len(), findings.len());
}

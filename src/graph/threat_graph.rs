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
    s.chars()
        .filter(|c| c.is_alphanumeric() || " ._-,:/()+@".contains(*c))
        .collect()
}

/// Strip CIDR suffix and reject empty/placeholder values. Returns `None` when
/// the input should not be treated as an attacker IP. Callers must never fall
/// back to hostname — hostnames are victim identifiers, not network origins.
fn parse_attacker_ip(raw: Option<&str>) -> Option<String> {
    let t = raw?.split('/').next()?.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("unknown") {
        return None;
    }
    Some(t.to_string())
}

/// Validate that a string looks like an IP address (v4 or v6).
fn validate_ip(ip: &str) -> bool {
    std::net::IpAddr::from_str(ip).is_ok()
        || ip
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
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

/// Count total nodes in the graph (used to detect a stale empty graph).
pub async fn count_graph_nodes(store: &dyn Database) -> usize {
    let results = query(store, "MATCH (n) RETURN count(n) AS cnt").await;
    results
        .first()
        .and_then(|r| r["cnt"].as_u64())
        .map(|n| n as usize)
        .unwrap_or(0)
}

/// Execute a Cypher mutation (CREATE/MERGE) — no return value needed.
pub async fn mutate(store: &dyn Database, cypher: &str) -> bool {
    match store.execute_cypher(cypher).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(
                "GRAPH: Cypher mutation failed: {e} | query: {}",
                &cypher[..cypher.len().min(120)]
            );
            false
        }
    }
}

// ══════════════════════════════════════════════════════════
// NODE UPSERTS — Add or update nodes in the graph
// ══════════════════════════════════════════════════════════

/// Upsert an IP node with enrichment data.
pub async fn upsert_ip(
    store: &dyn Database,
    addr: &str,
    country: Option<&str>,
    asn: Option<&str>,
    classification: Option<&str>,
) {
    if !validate_ip(addr) {
        tracing::warn!(
            "GRAPH: Invalid IP address, skipping upsert: {}",
            &addr[..addr.len().min(40)]
        );
        return;
    }
    let safe_addr = sanitize_cypher_value(addr);
    let mut sets = vec![format!("ip.addr = '{}'", safe_addr)];
    if let Some(c) = country {
        sets.push(format!("ip.country = '{}'", sanitize_cypher_value(c)));
    }
    if let Some(a) = asn {
        sets.push(format!("ip.asn = '{}'", sanitize_cypher_value(a)));
    }
    if let Some(c) = classification {
        sets.push(format!(
            "ip.classification = '{}'",
            sanitize_cypher_value(c)
        ));
    }
    sets.push(format!(
        "ip.last_seen = '{}'",
        chrono::Utc::now().to_rfc3339()
    ));

    let cypher = format!(
        "MERGE (ip:IP {{addr: '{}'}}) SET {} RETURN ip",
        safe_addr,
        sets.join(", ")
    );
    mutate(store, &cypher).await;
}

/// Upsert an Asset node.
///
/// Tolerant of legacy IDs that contain spaces or other minor punctuation:
/// the ID is normalized to a graph-safe form (spaces and forbidden chars
/// replaced by '-') instead of being rejected. The DB asset row keeps its
/// original ID, only the graph identifier is normalized.
pub async fn upsert_asset(
    store: &dyn Database,
    id: &str,
    hostname: &str,
    asset_type: &str,
    criticality: &str,
) {
    let id_norm = normalize_asset_id(id);
    if !validate_id(&id_norm) {
        tracing::warn!(
            "GRAPH: Asset ID still invalid after normalization, skipping: {}",
            &id[..id.len().min(40)]
        );
        return;
    }
    // criticality wrappée dans coalesce() pour préserver une criticality
    // déjà définie (ex. par path_risk::seed_path_risk_attributes). Sans
    // ça, chaque sync ramènerait tous les assets à 'low' et les batches
    // predictive paths ne trouveraient jamais de critical target.
    //
    // Note: Apache AGE ne supporte pas la syntaxe `ON CREATE SET /
    // ON MATCH SET` — coalesce dans un SET expression est l'équivalent
    // sémantique compatible.
    let cypher = format!(
        "MERGE (a:Asset {{id: '{id}'}}) \
         SET a.hostname = '{host}', a.type = '{ty}', \
             a.criticality = coalesce(a.criticality, '{crit}'), \
             a.last_seen = '{ts}' \
         RETURN a",
        id = sanitize_cypher_value(&id_norm),
        host = sanitize_cypher_value(hostname),
        ty = sanitize_cypher_value(asset_type),
        crit = sanitize_cypher_value(criticality),
        ts = chrono::Utc::now().to_rfc3339()
    );
    mutate(store, &cypher).await;
}

/// Sprint 3 #2 — RSSI manual override of an asset's criticality.
///
/// Unlike `upsert_asset` (which uses `coalesce` to preserve a value already
/// set by the heuristic seeder), this writes the new value unconditionally.
/// `MERGE` keeps the call idempotent if the asset isn't yet in the graph.
pub async fn set_asset_criticality_graph(store: &dyn Database, id: &str, criticality: &str) -> bool {
    let id_norm = normalize_asset_id(id);
    if !validate_id(&id_norm) {
        tracing::warn!(
            "GRAPH: set_asset_criticality refused invalid id: {}",
            &id[..id.len().min(40)]
        );
        return false;
    }
    let cypher = format!(
        "MERGE (a:Asset {{id: '{id}'}}) SET a.criticality = '{crit}' RETURN a",
        id = sanitize_cypher_value(&id_norm),
        crit = sanitize_cypher_value(criticality),
    );
    mutate(store, &cypher).await
}

/// Normalize an asset ID for graph use: lowercase + replace whitespace and
/// disallowed characters by '-'. Keeps a-z, 0-9, '-', '_', '.'.
fn normalize_asset_id(id: &str) -> String {
    id.trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Upsert a CVE node.
pub async fn upsert_cve(store: &dyn Database, cve_id: &str, cvss: f64, epss: f64, in_kev: bool) {
    if !validate_id(cve_id) {
        tracing::warn!(
            "GRAPH: Invalid CVE ID, skipping upsert: {}",
            &cve_id[..cve_id.len().min(40)]
        );
        return;
    }
    let cypher = format!(
        "MERGE (c:CVE {{id: '{}'}}) SET c.cvss = {}, c.epss = {}, c.in_kev = {} RETURN c",
        sanitize_cypher_value(cve_id),
        cvss,
        epss,
        in_kev
    );
    mutate(store, &cypher).await;
}

/// Upsert a MITRE ATT&CK Technique node.
pub async fn upsert_technique(store: &dyn Database, mitre_id: &str, name: &str, tactic: &str) {
    if !validate_id(mitre_id) {
        tracing::warn!(
            "GRAPH: Invalid MITRE ID, skipping upsert: {}",
            &mitre_id[..mitre_id.len().min(40)]
        );
        return;
    }
    let cypher = format!(
        "MERGE (t:Technique {{mitre_id: '{}'}}) SET t.name = '{}', t.tactic = '{}' RETURN t",
        sanitize_cypher_value(mitre_id),
        sanitize_cypher_value(name),
        sanitize_cypher_value(tactic)
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
        sanitize_cypher_value(ip_addr),
        sanitize_cypher_value(asset_id),
        sanitize_cypher_value(method),
        chrono::Utc::now().to_rfc3339()
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
        sanitize_cypher_value(cve_id),
        sanitize_cypher_value(asset_id)
    );
    mutate(store, &cypher).await;
}

// ══════════════════════════════════════════════════════════
// INVESTIGATION QUERIES — Power the deterministic pipeline
// ══════════════════════════════════════════════════════════

/// Find all IPs that have attacked a specific asset.
pub async fn find_attackers(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    if !validate_id(asset_id) {
        return vec![];
    }
    query(
        store,
        &format!(
            "MATCH (ip:IP)-[att:ATTACKS]->(a:Asset {{id: '{}'}}) \
         RETURN ip.addr, ip.country, ip.classification, att.method",
            sanitize_cypher_value(asset_id)
        ),
    )
    .await
}

/// Find all CVEs affecting an asset (especially KEV).
pub async fn find_asset_cves(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    if !validate_id(asset_id) {
        return vec![];
    }
    query(store, &format!(
        "MATCH (c:CVE)-[:AFFECTS]->(a:Asset {{id: '{}'}}) RETURN c.id, c.cvss, c.epss, c.in_kev",
        sanitize_cypher_value(asset_id)
    )).await
}

/// Find all assets attacked by a specific IP.
pub async fn find_ip_targets(store: &dyn Database, ip_addr: &str) -> Vec<serde_json::Value> {
    if !validate_ip(ip_addr) {
        return vec![];
    }
    query(store, &format!(
        "MATCH (ip:IP {{addr: '{}'}})-[:ATTACKS]->(a:Asset) RETURN a.id, a.hostname, a.criticality",
        sanitize_cypher_value(ip_addr)
    )).await
}

/// Build full investigation context for an asset (for L2 Reasoning).
/// Includes attackers, CVEs, and analyst notes from the graph.
pub async fn build_investigation_context(
    store: &dyn Database,
    asset_id: &str,
) -> serde_json::Value {
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
    use crate::agent::ip_classifier;
    use crate::db::threatclaw_store::ThreatClawStore;

    // ── Incremental sync: only process data newer than last sync ──
    let last_sync = store
        .get_setting("_system", "last_graph_sync")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "2020-01-01T00:00:00Z".to_string());

    // ── Load assets from the new assets table ──
    let assets = store
        .list_assets(None, Some("active"), 500, 0)
        .await
        .unwrap_or_default();
    let mut asset_ip_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

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
    let networks: Vec<ip_classifier::NetworkRange> = networks_db
        .iter()
        .filter_map(|n| {
            ip_classifier::NetworkRange::from_cidr(
                &n.cidr,
                n.label.as_deref().unwrap_or(""),
                &n.zone,
            )
        })
        .collect();
    let known_ips: Vec<String> = asset_ip_map.keys().cloned().collect();

    // ── Process alerts — classify IPs and create graph relationships ──
    // Full scan when:
    //   - assets table is empty (first run, auto-discovery), OR
    //   - the graph is suspiciously small (<20 nodes) which usually means
    //     last_graph_sync drifted ahead of the actual data and the
    //     incremental filter never matched anything
    let graph_almost_empty = count_graph_nodes(store).await < 20;
    let force_full = assets.is_empty() || graph_almost_empty;
    let all_alerts = store
        .list_alerts(None, None, 5000, 0)
        .await
        .unwrap_or_default();
    let alerts: Vec<_> = if force_full {
        if graph_almost_empty {
            tracing::warn!("GRAPH: Graph is nearly empty — forcing full alert rescan to backfill");
        } else {
            tracing::info!("GRAPH: No assets in DB — running full alert scan for auto-discovery");
        }
        all_alerts
    } else {
        all_alerts
            .into_iter()
            .filter(|a| a.matched_at.as_str() > last_sync.as_str())
            .collect()
    };
    for a in &alerts {
        let victim_id = a.hostname.as_deref().and_then(|h| {
            let trimmed = h.trim();
            if trimmed.is_empty() {
                return None;
            }
            asset_ip_map
                .get(trimmed)
                .cloned()
                .or_else(|| asset_ip_map.get(&trimmed.to_lowercase()).cloned())
        });

        let source_ip_clean = parse_attacker_ip(a.source_ip.as_deref());

        if let Some(clean_ip) = source_ip_clean.as_deref() {
            let classification = ip_classifier::classify(clean_ip, &networks, &known_ips);

            match classification {
                ip_classifier::IpClass::External => {
                    upsert_ip(store, clean_ip, None, None, Some("suspicious")).await;
                    if let Some(ref victim_id) = victim_id {
                        record_attack(store, clean_ip, victim_id, &a.title).await;
                    }
                }
                ip_classifier::IpClass::InternalKnown(ref asset_id) => {
                    if let Some(ref victim_id) = victim_id
                        && victim_id != asset_id
                    {
                        upsert_ip(store, clean_ip, None, None, Some("lateral")).await;
                        record_attack(store, clean_ip, victim_id, &format!("lateral: {}", a.title))
                            .await;
                    }
                }
                ip_classifier::IpClass::InternalUnknown => {
                    // Unknown device on internal network — auto-create asset
                    let auto_id = format!("auto-{}", clean_ip.replace('.', "-"));
                    if !asset_ip_map.contains_key(clean_ip) {
                        let _ = store
                            .upsert_asset(&crate::db::threatclaw_store::NewAsset {
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
                                services: serde_json::json!([]),
                                source: "alert-auto".into(),
                                owner: None,
                                location: None,
                                tags: vec!["auto-discovered".into()],
                            })
                            .await;
                        upsert_asset(store, &auto_id, clean_ip, "unknown", "medium").await;
                        asset_ip_map.insert(clean_ip.to_string(), auto_id.clone());
                        tracing::info!(
                            "GRAPH: Auto-created unknown asset {} for internal IP {}",
                            auto_id,
                            clean_ip
                        );
                    }
                    upsert_ip(store, clean_ip, None, None, Some("unknown-internal")).await;
                }
                ip_classifier::IpClass::Special => {} // ignore loopback, multicast
            }
        }

        if let Some(ref victim_id) = victim_id {
            let host_display = a.hostname.as_deref().unwrap_or("").trim();
            if let Some(asset) = assets.iter().find(|aa| aa.id == *victim_id) {
                upsert_asset(
                    store,
                    victim_id,
                    host_display,
                    &asset.category,
                    &asset.criticality,
                )
                .await;
            }
        }
    }

    // ── Sync CVEs from findings ──
    // Only process findings newer than last sync for incremental updates
    let all_findings = store
        .list_findings(None, Some("open"), None, 200, 0)
        .await
        .unwrap_or_default();
    let findings: Vec<_> = all_findings
        .into_iter()
        .filter(|f| f.detected_at.as_str() > last_sync.as_str())
        .collect();
    for f in &findings {
        if let Some(cve) = f
            .metadata
            .as_object()
            .and_then(|m| m.get("cve"))
            .and_then(|v| v.as_str())
        {
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

    // ── Store last sync timestamp for incremental updates ──
    let _ = store
        .set_setting(
            "_system",
            "last_graph_sync",
            &serde_json::json!(chrono::Utc::now().to_rfc3339()),
        )
        .await;

    tracing::info!(
        "GRAPH: Synced from DB — {} assets, {} alerts (new), {} findings (new)",
        assets.len() + targets.len(),
        alerts.len(),
        findings.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ip_rejects_hostname() {
        // Regression: Wazuh alerts with empty source_ip and hostname="TARS-HOST"
        // used to fall back to hostname, reach upsert_ip, and spam the logs with
        // "Invalid IP address, skipping upsert: TARS-HOST" on every cycle.
        assert!(!validate_ip("TARS-HOST"));
        assert!(!validate_ip("case"));
        assert!(!validate_ip("pc-compta.lan"));
        assert!(validate_ip("192.168.1.1"));
        assert!(validate_ip("10.10.10.2"));
        assert!(validate_ip("2001:db8::1"));
    }

    #[test]
    fn parse_attacker_ip_strips_cidr_and_rejects_empty() {
        assert_eq!(
            parse_attacker_ip(Some("192.168.1.1")),
            Some("192.168.1.1".into())
        );
        assert_eq!(
            parse_attacker_ip(Some("10.0.0.1/24")),
            Some("10.0.0.1".into())
        );
        assert_eq!(
            parse_attacker_ip(Some("  10.0.0.1  ")),
            Some("10.0.0.1".into())
        );
        assert_eq!(parse_attacker_ip(Some("")), None);
        assert_eq!(parse_attacker_ip(Some("   ")), None);
        assert_eq!(parse_attacker_ip(Some("unknown")), None);
        assert_eq!(parse_attacker_ip(Some("UNKNOWN")), None);
        assert_eq!(parse_attacker_ip(None), None);
    }

    #[test]
    fn parse_attacker_ip_does_not_accept_hostname_shaped_inputs() {
        // The function itself does not validate IP syntax (that's validate_ip's job
        // downstream). But it must preserve the contract: an explicit hostname value
        // passed here is out of contract — callers must never pass a hostname.
        // We assert that whatever non-empty non-"unknown" string goes in, the downstream
        // validate_ip gatekeeps it correctly.
        let accidental = parse_attacker_ip(Some("TARS-HOST"));
        assert!(accidental.is_some(), "parser is permissive by design");
        assert!(
            !validate_ip(&accidental.unwrap()),
            "validate_ip must reject hostnames reaching upsert_ip"
        );
    }
}

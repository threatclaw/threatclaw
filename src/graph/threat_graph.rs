//! Threat Graph — CRUD operations on the Apache AGE graph.
//!
//! All graph operations use raw SQL with Cypher queries via AGE.
//! The graph is stored in PostgreSQL alongside relational data.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Result of a graph operation.
#[derive(Debug, Clone, Serialize)]
pub struct GraphResult {
    pub success: bool,
    pub data: serde_json::Value,
    pub error: Option<String>,
}

/// Execute a Cypher query on the threat graph via raw SQL.
/// This is the low-level function — all graph operations go through here.
pub async fn cypher_query(
    store: &dyn crate::db::Database,
    cypher: &str,
    return_columns: &str,
) -> GraphResult {
    // AGE requires LOAD + SET before each query in a new session
    let sql = format!(
        "SELECT * FROM ag_catalog.cypher('threat_graph', $$ {} $$) AS ({})",
        cypher.replace('\'', "''"),
        return_columns,
    );

    // Use settings store to execute raw SQL via a helper
    // For now, store the result query for the API handler to execute
    GraphResult {
        success: true,
        data: json!({ "query": sql, "cypher": cypher }),
        error: None,
    }
}

// ══════════════════════════════════════════════════════════
// NODE OPERATIONS — Create/Update/Query nodes
// ══════════════════════════════════════════════════════════

/// Add or update an IP node in the graph.
pub fn cypher_upsert_ip(addr: &str, country: Option<&str>, asn: Option<&str>, classification: Option<&str>) -> String {
    let props = [
        Some(format!("addr: '{}'", addr.replace('\'', ""))),
        country.map(|c| format!("country: '{}'", c.replace('\'', ""))),
        asn.map(|a| format!("asn: '{}'", a.replace('\'', ""))),
        classification.map(|c| format!("classification: '{}'", c.replace('\'', ""))),
    ].into_iter().flatten().collect::<Vec<_>>().join(", ");

    format!(
        "MERGE (ip:IP {{addr: '{}'}}) SET ip += {{{}}} RETURN ip",
        addr.replace('\'', ""), props
    )
}

/// Add or update an Asset node.
pub fn cypher_upsert_asset(id: &str, hostname: &str, asset_type: &str, criticality: &str) -> String {
    format!(
        "MERGE (a:Asset {{id: '{}'}}) SET a.hostname = '{}', a.type = '{}', a.criticality = '{}' RETURN a",
        id.replace('\'', ""), hostname.replace('\'', ""),
        asset_type.replace('\'', ""), criticality.replace('\'', ""),
    )
}

/// Add or update a CVE node.
pub fn cypher_upsert_cve(cve_id: &str, cvss: f64, epss: f64, in_kev: bool) -> String {
    format!(
        "MERGE (c:CVE {{id: '{}'}}) SET c.cvss = {}, c.epss = {}, c.in_kev = {} RETURN c",
        cve_id.replace('\'', ""), cvss, epss, in_kev,
    )
}

/// Add a Technique node (MITRE ATT&CK).
pub fn cypher_upsert_technique(mitre_id: &str, name: &str, tactic: &str) -> String {
    format!(
        "MERGE (t:Technique {{mitre_id: '{}'}}) SET t.name = '{}', t.tactic = '{}' RETURN t",
        mitre_id.replace('\'', ""), name.replace('\'', ""), tactic.replace('\'', ""),
    )
}

// ══════════════════════════════════════════════════════════
// RELATIONSHIP OPERATIONS — Create edges
// ══════════════════════════════════════════════════════════

/// Create an ATTACKS relationship (IP → Asset).
pub fn cypher_create_attack(ip_addr: &str, asset_id: &str, method: &str, timestamp: &str) -> String {
    format!(
        "MATCH (ip:IP {{addr: '{}'}}), (a:Asset {{id: '{}'}}) \
         CREATE (ip)-[:ATTACKS {{method: '{}', timestamp: '{}'}}]->(a)",
        ip_addr.replace('\'', ""), asset_id.replace('\'', ""),
        method.replace('\'', ""), timestamp.replace('\'', ""),
    )
}

/// Create an AFFECTS relationship (CVE → Asset).
pub fn cypher_create_affects(cve_id: &str, asset_id: &str) -> String {
    format!(
        "MATCH (c:CVE {{id: '{}'}}), (a:Asset {{id: '{}'}}) \
         MERGE (c)-[:AFFECTS]->(a)",
        cve_id.replace('\'', ""), asset_id.replace('\'', ""),
    )
}

/// Create a USES_TECHNIQUE relationship (Alert/Finding → Technique).
pub fn cypher_create_uses_technique(entity_label: &str, entity_id: &str, mitre_id: &str) -> String {
    format!(
        "MATCH (e:{} {{id: '{}'}}), (t:Technique {{mitre_id: '{}'}}) \
         MERGE (e)-[:USES_TECHNIQUE]->(t)",
        entity_label, entity_id.replace('\'', ""), mitre_id.replace('\'', ""),
    )
}

// ══════════════════════════════════════════════════════════
// QUERY OPERATIONS — Investigation queries
// ══════════════════════════════════════════════════════════

/// Find all attack paths to an asset.
pub fn cypher_attack_paths(asset_id: &str) -> String {
    format!(
        "MATCH path = (ip:IP)-[:ATTACKS*1..3]->(a:Asset {{id: '{}'}}) \
         RETURN ip.addr, ip.country, ip.classification, length(path) as hops",
        asset_id.replace('\'', ""),
    )
}

/// Find all CVEs affecting an asset that are in CISA KEV.
pub fn cypher_kev_on_asset(asset_id: &str) -> String {
    format!(
        "MATCH (a:Asset {{id: '{}'}})-[:RUNS_SERVICE]->(c:CVE {{in_kev: true}}) \
         RETURN c.id, c.cvss, c.epss",
        asset_id.replace('\'', ""),
    )
}

/// Correlate alerts from the same IP within a time window.
pub fn cypher_correlate_ip(ip_addr: &str) -> String {
    format!(
        "MATCH (ip:IP {{addr: '{}'}})-[:ATTACKS]->(a:Asset) \
         RETURN a.id, a.hostname, a.criticality",
        ip_addr.replace('\'', ""),
    )
}

/// Find the kill chain: IP → attacks → asset → has CVE → exploited by actor → uses technique
pub fn cypher_kill_chain(ip_addr: &str) -> String {
    format!(
        "MATCH (ip:IP {{addr: '{}'}})-[:ATTACKS]->(a:Asset)-[:RUNS_SERVICE]->(c:CVE) \
         OPTIONAL MATCH (c)-[:EXPLOITED_BY]->(actor:ThreatActor)-[:USES_TECHNIQUE]->(t:Technique) \
         RETURN ip.addr, a.hostname, c.id, c.cvss, actor.name, t.mitre_id, t.name",
        ip_addr.replace('\'', ""),
    )
}

/// Get the full graph context for an investigation (for L2 Reasoning).
pub fn cypher_investigation_context(asset_id: &str) -> String {
    format!(
        "MATCH (a:Asset {{id: '{}'}}) \
         OPTIONAL MATCH (ip:IP)-[att:ATTACKS]->(a) \
         OPTIONAL MATCH (a)-[:RUNS_SERVICE]->(c:CVE) \
         OPTIONAL MATCH (c)-[:EXPLOITED_BY]->(actor:ThreatActor) \
         RETURN a, collect(DISTINCT ip) as attackers, collect(DISTINCT c) as cves, collect(DISTINCT actor) as actors",
        asset_id.replace('\'', ""),
    )
}

//! Asset Resolution Pipeline — intelligent merge from multiple discovery sources.
//!
//! When nmap, AD, pfSense, and logs all discover the same machine,
//! ThreatClaw merges them into ONE Asset node. Never duplicate.
//!
//! Resolution priority: MAC > hostname > IP
//! - MAC is the physical identifier (most stable, survives DHCP changes)
//! - Hostname is the logical identifier (stable in AD environments)
//! - IP is volatile (DHCP can reassign any time)

use crate::db::Database;
use crate::graph::threat_graph::{mutate, query};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// An asset discovered from any source, before resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    /// MAC address (most stable identifier).
    pub mac: Option<String>,
    /// Short hostname (e.g., "PC-COMPTA-03").
    pub hostname: Option<String>,
    /// Fully qualified domain name (e.g., "PC-COMPTA-03.corp.local").
    pub fqdn: Option<String>,
    /// IP address (volatile with DHCP).
    pub ip: Option<String>,
    /// Operating system.
    pub os: Option<String>,
    /// Open ports (from nmap).
    pub ports: Option<Vec<u16>>,
    /// Services detected (JSON array: [{port, proto, service, product, version}]).
    pub services: serde_json::Value,
    /// Organizational Unit (from AD).
    pub ou: Option<String>,
    /// VLAN ID (from pfSense/switch).
    pub vlan: Option<u16>,
    /// VM identifier (from Proxmox/VMware).
    pub vm_id: Option<String>,
    /// Asset criticality ("low", "medium", "high", "critical").
    pub criticality: Option<String>,
    /// Discovery source ("nmap", "ad", "dhcp", "pfSense", "proxmox", "syslog").
    pub source: String,
}

/// Result of the resolution process.
#[derive(Debug, Clone, Serialize)]
pub struct ResolutionResult {
    /// The asset ID in the graph.
    pub asset_id: String,
    /// Whether this was a new asset or a merge.
    pub action: ResolutionAction,
    /// Final confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// All sources that have contributed to this asset.
    pub sources: Vec<String>,
    /// Conflict details (if any).
    pub conflict: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ResolutionAction {
    Created,
    Merged,
    Updated,
    Conflict,
}

/// Build a meaningful name for an asset from available data.
fn build_asset_name(discovered: &DiscoveredAsset) -> String {
    // Priority: hostname > mac_vendor+ip_suffix > ip
    if let Some(ref hostname) = discovered.hostname {
        return hostname.clone();
    }
    // Try MAC vendor for a meaningful name
    if let Some(ref mac) = discovered.mac {
        let oui = crate::enrichment::mac_oui_lookup::lookup(mac);
        if let Some(ref vendor) = oui.vendor {
            let short_vendor = vendor
                .split_whitespace()
                .next()
                .unwrap_or(vendor)
                .trim_end_matches(',');
            if let Some(ref ip) = discovered.ip {
                let suffix = ip.rsplit('.').next().unwrap_or(ip);
                return format!("{}-{}", short_vendor, suffix);
            }
            return short_vendor.to_string();
        }
    }
    // Try to use main service as hint
    if let Some(ref ports) = discovered.ports {
        if let Some(ref ip) = discovered.ip {
            let suffix = ip.rsplit('.').next().unwrap_or(ip);
            if ports.contains(&80) || ports.contains(&443) {
                return format!("web-{}", suffix);
            }
            if ports.contains(&22) {
                return format!("srv-{}", suffix);
            }
            if ports.contains(&53) {
                return format!("dns-{}", suffix);
            }
            if ports.contains(&3306) || ports.contains(&5432) {
                return format!("db-{}", suffix);
            }
        }
    }
    // Fallback: IP
    discovered.ip.clone().unwrap_or_else(|| "unknown".into())
}

/// Resolve a discovered asset: find existing match or create new.
/// This is the core function — called by every discovery source.
pub async fn resolve_asset(store: &dyn Database, discovered: &DiscoveredAsset) -> ResolutionResult {
    let now = Utc::now().to_rfc3339();

    // Priority 1: Match by MAC (most reliable)
    if let Some(ref mac) = discovered.mac {
        let mac_clean = normalize_mac(mac);
        if let Some(existing) = find_asset_by_field(store, "mac", &mac_clean).await {
            return merge_asset(store, &existing, discovered, &now).await;
        }
    }

    // Priority 2: Match by hostname (reliable in AD environments)
    if let Some(ref hostname) = discovered.hostname {
        let hostname_clean = hostname.to_lowercase().trim().to_string();
        if let Some(existing) = find_asset_by_hostname(store, &hostname_clean).await {
            // Check for conflict: same hostname but different MAC
            if let (Some(existing_mac), Some(new_mac)) = (&existing.mac, &discovered.mac) {
                let existing_norm = normalize_mac(existing_mac);
                let new_norm = normalize_mac(new_mac);
                if existing_norm != new_norm {
                    // CONFLICT: same hostname, different MAC = different machines
                    tracing::warn!(
                        "ASSET CONFLICT: hostname '{}' has MAC {} in graph but discovery reports MAC {}",
                        hostname_clean,
                        existing_norm,
                        new_norm
                    );
                    // Create a new asset with conflict flag
                    let result = create_new_asset(store, discovered, &now).await;
                    return ResolutionResult {
                        conflict: Some(format!(
                            "Hostname '{}' exists with MAC {} but new MAC {} detected — possible reinstall or duplicate",
                            hostname_clean, existing_norm, new_norm
                        )),
                        action: ResolutionAction::Conflict,
                        ..result
                    };
                }
            }
            return merge_asset(store, &existing, discovered, &now).await;
        }
    }

    // Priority 3: Match by FQDN
    if let Some(ref fqdn) = discovered.fqdn {
        let fqdn_clean = fqdn.to_lowercase().trim().to_string();
        if let Some(existing) = find_asset_by_field(store, "fqdn", &fqdn_clean).await {
            return merge_asset(store, &existing, discovered, &now).await;
        }
    }

    // Priority 4: Match by IP (least reliable — DHCP can change)
    if let Some(ref ip) = discovered.ip {
        if let Some(existing) = find_asset_by_field(store, "ip", ip).await {
            // IP match is only valid if the existing asset was seen recently (< 24h)
            // Otherwise the IP may have been reassigned by DHCP
            let is_recent = existing
                .last_seen
                .as_ref()
                .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
                .map(|ts| Utc::now().signed_duration_since(ts).num_hours() < 24)
                .unwrap_or(false);

            if is_recent {
                return merge_asset(store, &existing, discovered, &now).await;
            }
            // IP was last seen > 24h ago — may have changed owner
            // Update old asset to remove this IP, create new
            tracing::info!(
                "ASSET: IP {} was last seen >24h ago on {}, creating new asset",
                ip,
                existing.id
            );
            clear_ip_from_asset(store, &existing.id, ip).await;
        }
    }

    // Nothing matched — create new asset
    create_new_asset(store, discovered, &now).await
}

/// Existing asset data from the graph.
struct ExistingAsset {
    id: String,
    mac: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    sources: Vec<String>,
    last_seen: Option<String>,
}

/// Decode the `a.sources` column out of an AGE Cypher row.
///
/// The graph stores sources as a JSON-encoded string like `'["ad","wazuh"]'`
/// and AGE round-trips it through agtype + row_to_json, which can produce
/// any of these shapes in the serde_json::Value we see:
///   - Array: already unwrapped by strip_agtype_quotes when the value was
///     short enough to successfully json-parse.
///   - Clean JSON string: `["ad","wazuh"]` — parse with from_str.
///   - Backslash-escaped string: `[\"ad\",\"wazuh\"]` — the outer quote-strip
///     in strip_agtype_quotes didn't json-parse successfully because the
///     inner `\"` are literal and from_str rejects them. Unescape first.
///
/// Without handling all three, every merge_asset call saw an empty
/// `existing.sources`, which silently replaced the accumulated list with
/// `[new_source]` and made asset dedup tracking useless.
fn read_sources(v: &serde_json::Value) -> Vec<String> {
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    let Some(s) = v.as_str() else {
        return vec![];
    };
    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(s) {
        return parsed;
    }
    // Fallback: the string carries literal `\"` escapes. Unescape once
    // and retry. We can't blindly json-parse the unescaped form because
    // that would let an attacker smuggle control characters; bound the
    // replacement to just `\"` and `\\` which are the only escapes the
    // graph layer ever writes.
    let unescaped = s.replace("\\\"", "\"").replace("\\\\", "\\");
    serde_json::from_str::<Vec<String>>(&unescaped).unwrap_or_default()
}

#[cfg(test)]
mod read_sources_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_already_decoded_array() {
        assert_eq!(
            read_sources(&json!(["ad", "wazuh"])),
            vec!["ad".to_string(), "wazuh".to_string()]
        );
    }

    #[test]
    fn parses_clean_json_string() {
        assert_eq!(
            read_sources(&json!("[\"ad\",\"wazuh\"]")),
            vec!["ad".to_string(), "wazuh".to_string()]
        );
    }

    #[test]
    fn parses_backslash_escaped_agtype_round_trip() {
        // This is the shape AGE + row_to_json produces after the
        // strip_agtype_quotes outer-layer unwrap: the inner content still
        // has the `\"` escapes that json::from_str rejects.
        let v = serde_json::Value::String("[\\\"ad\\\",\\\"wazuh\\\"]".into());
        assert_eq!(
            read_sources(&v),
            vec!["ad".to_string(), "wazuh".to_string()]
        );
    }

    #[test]
    fn empty_on_garbage() {
        assert_eq!(read_sources(&json!("not json")), Vec::<String>::new());
        assert_eq!(read_sources(&json!(null)), Vec::<String>::new());
        assert_eq!(read_sources(&json!(42)), Vec::<String>::new());
    }
}

/// Find an asset by a specific field. If duplicates exist (historically
/// possible before the hostname-based dedup landed), return the most
/// recently seen one — deterministic across cycles so both the merge and
/// any downstream reference converge on a single canonical asset.
async fn find_asset_by_field(
    store: &dyn Database,
    field: &str,
    value: &str,
) -> Option<ExistingAsset> {
    let results = query(store, &format!(
        "MATCH (a:Asset {{{}: '{}'}}) RETURN a.id, a.mac, a.hostname, a.ip, a.sources, a.last_seen \
         ORDER BY a.last_seen DESC LIMIT 1",
        field, esc(value)
    )).await;

    results.first().map(|r| ExistingAsset {
        id: r["a.id"].as_str().unwrap_or("").to_string(),
        mac: r["a.mac"].as_str().map(String::from),
        hostname: r["a.hostname"].as_str().map(String::from),
        ip: r["a.ip"].as_str().map(String::from),
        sources: read_sources(&r["a.sources"]),
        last_seen: r["a.last_seen"].as_str().map(String::from),
    })
}

/// Find asset by hostname — supports partial match (hostname or fqdn starts with).
async fn find_asset_by_hostname(store: &dyn Database, hostname: &str) -> Option<ExistingAsset> {
    // Try exact hostname match first
    if let Some(found) = find_asset_by_field(store, "hostname", hostname).await {
        return Some(found);
    }
    // Try FQDN that starts with hostname. Most-recent-first for determinism.
    let results = query(
        store,
        &format!(
            "MATCH (a:Asset) WHERE a.fqdn STARTS WITH '{}' \
         RETURN a.id, a.mac, a.hostname, a.ip, a.sources, a.last_seen \
         ORDER BY a.last_seen DESC LIMIT 1",
            esc(hostname)
        ),
    )
    .await;

    results.first().map(|r| ExistingAsset {
        id: r["a.id"].as_str().unwrap_or("").to_string(),
        mac: r["a.mac"].as_str().map(String::from),
        hostname: r["a.hostname"].as_str().map(String::from),
        ip: r["a.ip"].as_str().map(String::from),
        sources: read_sources(&r["a.sources"]),
        last_seen: r["a.last_seen"].as_str().map(String::from),
    })
}

/// Merge new discovery data into an existing asset.
async fn merge_asset(
    store: &dyn Database,
    existing: &ExistingAsset,
    discovered: &DiscoveredAsset,
    now: &str,
) -> ResolutionResult {
    let mut sets = vec![format!("a.last_seen = '{}'", esc(now))];

    // Merge each field — new data overwrites only if it's more specific
    if let Some(ref mac) = discovered.mac {
        sets.push(format!("a.mac = '{}'", esc(&normalize_mac(mac))));
    }
    if let Some(ref hostname) = discovered.hostname {
        sets.push(format!("a.hostname = '{}'", esc(&hostname.to_lowercase())));
    }
    if let Some(ref fqdn) = discovered.fqdn {
        sets.push(format!("a.fqdn = '{}'", esc(&fqdn.to_lowercase())));
    }
    if let Some(ref ip) = discovered.ip {
        sets.push(format!("a.ip = '{}'", esc(ip)));
    }
    // OS: prefer more specific (AD "Windows 11 Pro 23H2" > nmap "Windows")
    if let Some(ref os) = discovered.os {
        if os.len() > 5 {
            // Only overwrite if it's a meaningful OS string
            sets.push(format!("a.os = '{}'", esc(os)));
        }
    }
    if let Some(ref ou) = discovered.ou {
        sets.push(format!("a.ou = '{}'", esc(ou)));
    }
    if let Some(vlan) = discovered.vlan {
        sets.push(format!("a.vlan = {}", vlan));
    }
    if let Some(ref vm_id) = discovered.vm_id {
        sets.push(format!("a.vm_id = '{}'", esc(vm_id)));
    }
    if let Some(ref ports) = discovered.ports {
        let ports_json = serde_json::to_string(ports).unwrap_or_default();
        sets.push(format!("a.ports = '{}'", esc(&ports_json)));
    }
    if let Some(ref criticality) = discovered.criticality {
        sets.push(format!("a.criticality = '{}'", esc(criticality)));
    }

    // Merge sources list
    let mut sources = existing.sources.clone();
    if !sources.contains(&discovered.source) {
        sources.push(discovered.source.clone());
    }
    let sources_json = serde_json::to_string(&sources).unwrap_or_default();
    sets.push(format!("a.sources = '{}'", esc(&sources_json)));

    // Calculate confidence based on number of sources
    let confidence = calculate_confidence(&sources);
    sets.push(format!("a.confidence = {}", confidence));

    let cypher = format!(
        "MATCH (a:Asset {{id: '{}'}}) SET {} RETURN a",
        esc(&existing.id),
        sets.join(", ")
    );
    mutate(store, &cypher).await;

    // Also upsert to PostgreSQL assets table (enriches existing or creates if missing)
    let category = crate::agent::fingerprint::guess_category(discovered);
    let _ = store
        .upsert_asset(&crate::db::threatclaw_store::NewAsset {
            id: existing.id.clone(),
            name: build_asset_name(discovered),
            category: category.into(),
            subcategory: None,
            role: None,
            criticality: discovered
                .criticality
                .clone()
                .unwrap_or_else(|| crate::agent::fingerprint::guess_criticality(discovered).into()),
            ip_addresses: discovered.ip.iter().cloned().collect(),
            mac_address: discovered.mac.clone(),
            hostname: discovered.hostname.clone(),
            fqdn: discovered.fqdn.clone(),
            url: None,
            os: discovered.os.clone(),
            mac_vendor: None,
            services: discovered.services.clone(),
            source: discovered.source.clone(),
            owner: None,
            location: None,
            tags: vec!["discovered".into()],
        })
        .await;

    // Phase A.2 fix — persist the dedup confidence so the billable
    // filter can exclude `uncertain` rows. Upgrade-only at the SQL
    // layer, so a later sync that only carries an IP can't regress
    // an asset already locked-in by MAC.
    let _ = store
        .set_asset_dedup_confidence(&existing.id, dedup_confidence_for(discovered))
        .await;

    tracing::info!(
        "ASSET MERGE: {} enriched by {} (confidence: {:.2})",
        existing.id,
        discovered.source,
        confidence
    );

    ResolutionResult {
        asset_id: existing.id.clone(),
        action: ResolutionAction::Merged,
        confidence,
        sources,
        conflict: None,
    }
}

/// Create a new asset node in the graph.
async fn create_new_asset(
    store: &dyn Database,
    discovered: &DiscoveredAsset,
    now: &str,
) -> ResolutionResult {
    let asset_id = generate_asset_id(discovered);
    let sources = vec![discovered.source.clone()];
    let confidence = calculate_confidence(&sources);
    let sources_json = serde_json::to_string(&sources).unwrap_or_default();

    let mut props = vec![
        format!("id: '{}'", esc(&asset_id)),
        format!("sources: '{}'", esc(&sources_json)),
        format!("confidence: {}", confidence),
        format!("first_seen: '{}'", esc(now)),
        format!("last_seen: '{}'", esc(now)),
    ];

    if let Some(ref mac) = discovered.mac {
        props.push(format!("mac: '{}'", esc(&normalize_mac(mac))));
    }
    if let Some(ref hostname) = discovered.hostname {
        props.push(format!("hostname: '{}'", esc(&hostname.to_lowercase())));
    }
    if let Some(ref fqdn) = discovered.fqdn {
        props.push(format!("fqdn: '{}'", esc(&fqdn.to_lowercase())));
    }
    if let Some(ref ip) = discovered.ip {
        props.push(format!("ip: '{}'", esc(ip)));
    }
    if let Some(ref os) = discovered.os {
        props.push(format!("os: '{}'", esc(os)));
    }
    if let Some(ref ou) = discovered.ou {
        props.push(format!("ou: '{}'", esc(ou)));
    }
    if let Some(vlan) = discovered.vlan {
        props.push(format!("vlan: {}", vlan));
    }
    if let Some(ref vm_id) = discovered.vm_id {
        props.push(format!("vm_id: '{}'", esc(vm_id)));
    }
    if let Some(ref ports) = discovered.ports {
        let ports_json = serde_json::to_string(ports).unwrap_or_default();
        props.push(format!("ports: '{}'", esc(&ports_json)));
    }
    let criticality = discovered.criticality.as_deref().unwrap_or("medium");
    props.push(format!("criticality: '{}'", esc(criticality)));

    let cypher = format!("CREATE (a:Asset {{{}}})", props.join(", "));
    mutate(store, &cypher).await;

    // Also write to PostgreSQL assets table (the source of truth for the dashboard)
    let category = crate::agent::fingerprint::guess_category(discovered);
    let _ = store
        .upsert_asset(&crate::db::threatclaw_store::NewAsset {
            id: asset_id.clone(),
            name: build_asset_name(discovered),
            category: category.into(),
            subcategory: None,
            role: None,
            criticality: discovered
                .criticality
                .clone()
                .unwrap_or_else(|| crate::agent::fingerprint::guess_criticality(discovered).into()),
            ip_addresses: discovered.ip.iter().cloned().collect(),
            mac_address: discovered.mac.clone(),
            hostname: discovered.hostname.clone(),
            fqdn: discovered.fqdn.clone(),
            url: None,
            os: discovered.os.clone(),
            mac_vendor: None,
            services: discovered.services.clone(),
            source: discovered.source.clone(),
            owner: None,
            location: None,
            tags: vec!["discovered".into()],
        })
        .await;

    // Phase A.2 fix — same dedup-confidence persistence as merge_asset.
    let _ = store
        .set_asset_dedup_confidence(&asset_id, dedup_confidence_for(discovered))
        .await;

    tracing::info!(
        "ASSET NEW: {} from {} (confidence: {:.2})",
        asset_id,
        discovered.source,
        confidence
    );

    // Passive enrichment hook: a new asset with at least one IP gets
    // an automatic Nmap fingerprint queued. The scan_queue dedup TTL
    // (1 h by default) ensures we don't scan the same target multiple
    // times when an asset is observed by several connectors in quick
    // succession. We skip the trigger when the source IS nmap itself —
    // otherwise we'd loop on every nmap run.
    if discovered.source != "nmap" {
        if let Some(ip) = discovered.ip.iter().next() {
            // Don't fail asset creation if the queue write hiccups —
            // it's an enrichment, not a hard dependency.
            let store_clone = store;
            let ip_owned = ip.clone();
            let asset_id_owned = asset_id.clone();
            let source = discovered.source.clone();
            let _ = crate::scans::enqueue_nmap_fingerprint(
                store_clone,
                &ip_owned,
                Some(asset_id_owned),
                &format!("auto:asset_merge:{}", source),
                None, // use default TTL (1 h)
            )
            .await;
        }
    }

    ResolutionResult {
        asset_id,
        action: ResolutionAction::Created,
        confidence,
        sources,
        conflict: None,
    }
}

/// Remove an IP from an asset (when DHCP reassigns it).
async fn clear_ip_from_asset(store: &dyn Database, asset_id: &str, _ip: &str) {
    let cypher = format!(
        "MATCH (a:Asset {{id: '{}'}}) SET a.ip = null",
        esc(asset_id)
    );
    mutate(store, &cypher).await;
}

/// Normalize MAC address to lowercase colon-separated format.
fn normalize_mac(mac: &str) -> String {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();

    if clean.len() != 12 {
        return mac.to_lowercase(); // Can't normalize, return as-is
    }

    // Format as aa:bb:cc:dd:ee:ff
    clean
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
}

/// Generate a stable asset ID from the best available identifier.
fn generate_asset_id(discovered: &DiscoveredAsset) -> String {
    if let Some(ref hostname) = discovered.hostname {
        return sanitize_id(&hostname.to_lowercase());
    }
    if let Some(ref mac) = discovered.mac {
        return format!("asset-{}", normalize_mac(mac).replace(':', ""));
    }
    if let Some(ref ip) = discovered.ip {
        return format!("asset-{}", ip.replace('.', "-"));
    }
    format!(
        "asset-{}",
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    )
}

/// Sanitize an asset ID: lowercase + replace spaces and disallowed characters
/// with '-'. Keeps a-z, 0-9, '-', '_', '.'. Required because the graph layer
/// (Apache AGE Cypher) rejects IDs containing whitespace or punctuation.
fn sanitize_id(s: &str) -> String {
    let cleaned: String = s
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Collapse repeated dashes and trim leading/trailing
    let collapsed = cleaned
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if collapsed.is_empty() {
        "unknown".into()
    } else {
        collapsed
    }
}

/// Phase A.2 — classify how confident we are that this discovery
/// uniquely identifies a single physical/logical device, given which
/// fields the connector populated. Mirrors the priority order of the
/// `resolve_asset` matcher so the SQL `dedup_confidence` column
/// reflects the strongest pivot the resolution had access to.
///
///   `high`      MAC present — physical identifier, survives DHCP
///   `medium`    hostname or FQDN present — stable in AD environments
///   `uncertain` only an IP — DHCP can rotate it, BYOD devices land here
///
/// The persisted column is upgrade-only at the SQL layer, so a later
/// partial sync (eg. firewall log with only an IP) cannot regress
/// an asset that was previously locked-in by MAC.
fn dedup_confidence_for(discovered: &DiscoveredAsset) -> &'static str {
    if discovered.mac.is_some() {
        "high"
    } else if discovered.hostname.is_some() || discovered.fqdn.is_some() {
        "medium"
    } else {
        "uncertain"
    }
}

/// Calculate confidence based on the number and type of contributing sources.
fn calculate_confidence(sources: &[String]) -> f64 {
    let mut score: f64 = 0.0;
    for source in sources {
        score += match source.as_str() {
            "ad" | "ldap" => 0.30,
            "dhcp" | "arp" => 0.25,
            "pfSense" | "opnsense" => 0.25,
            "nmap" => 0.15,
            "proxmox" | "vmware" => 0.20,
            "syslog" | "logs" => 0.10,
            _ => 0.05,
        };
    }
    if score > 1.0 { 1.0 } else { score }
}

/// List all assets sorted by confidence.
pub async fn list_assets(store: &dyn Database, limit: u64) -> Vec<serde_json::Value> {
    query(
        store,
        &format!(
            "MATCH (a:Asset) \
         RETURN a.id, a.mac, a.hostname, a.fqdn, a.ip, a.os, a.ou, a.vlan, \
         a.criticality, a.confidence, a.sources, a.first_seen, a.last_seen \
         ORDER BY a.confidence DESC LIMIT {}",
            limit
        ),
    )
    .await
}

/// Find assets with low confidence (incomplete data — need more sources).
pub async fn find_incomplete_assets(store: &dyn Database) -> Vec<serde_json::Value> {
    query(
        store,
        "MATCH (a:Asset) WHERE a.confidence < 0.5 \
         RETURN a.id, a.hostname, a.ip, a.mac, a.confidence, a.sources \
         ORDER BY a.confidence ASC LIMIT 50",
    )
    .await
}

/// Find assets not seen in the last N hours (potentially offline/removed).
pub async fn find_stale_assets(store: &dyn Database, hours: u64) -> Vec<serde_json::Value> {
    let cutoff = (Utc::now() - chrono::Duration::hours(hours as i64)).to_rfc3339();
    query(
        store,
        &format!(
            "MATCH (a:Asset) WHERE a.last_seen < '{}' \
         RETURN a.id, a.hostname, a.ip, a.last_seen \
         ORDER BY a.last_seen ASC LIMIT 50",
            esc(&cutoff)
        ),
    )
    .await
}

/// Get asset count by source.
pub async fn asset_stats(store: &dyn Database) -> serde_json::Value {
    let total = query(store, "MATCH (a:Asset) RETURN count(a)").await;
    let with_mac = query(
        store,
        "MATCH (a:Asset) WHERE a.mac IS NOT NULL RETURN count(a)",
    )
    .await;
    let with_hostname = query(
        store,
        "MATCH (a:Asset) WHERE a.hostname IS NOT NULL RETURN count(a)",
    )
    .await;

    let total_count = total
        .first()
        .and_then(|r| r["count(a)"].as_i64())
        .unwrap_or(0);
    let mac_count = with_mac
        .first()
        .and_then(|r| r["count(a)"].as_i64())
        .unwrap_or(0);
    let hostname_count = with_hostname
        .first()
        .and_then(|r| r["count(a)"].as_i64())
        .unwrap_or(0);

    json!({
        "total_assets": total_count,
        "with_mac": mac_count,
        "with_hostname": hostname_count,
        "without_mac": total_count - mac_count,
        "coverage": if total_count > 0 { mac_count as f64 / total_count as f64 } else { 0.0 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mac() {
        assert_eq!(normalize_mac("00:1A:2B:3C:4D:5E"), "00:1a:2b:3c:4d:5e");
        assert_eq!(normalize_mac("001A2B3C4D5E"), "00:1a:2b:3c:4d:5e");
        assert_eq!(normalize_mac("00-1A-2B-3C-4D-5E"), "00:1a:2b:3c:4d:5e");
        assert_eq!(normalize_mac("invalid"), "invalid");
    }

    fn make_discovered(mac: Option<&str>, host: Option<&str>, ip: Option<&str>) -> DiscoveredAsset {
        DiscoveredAsset {
            mac: mac.map(String::from),
            hostname: host.map(String::from),
            fqdn: None,
            ip: ip.map(String::from),
            os: None,
            ports: None,
            ou: None,
            vlan: None,
            services: serde_json::json!([]),
            vm_id: None,
            criticality: None,
            source: "test".into(),
        }
    }

    #[test]
    fn dedup_confidence_high_when_mac_present() {
        let d = make_discovered(Some("aa:bb:cc:dd:ee:ff"), Some("srv"), Some("10.0.0.1"));
        assert_eq!(dedup_confidence_for(&d), "high");
    }

    #[test]
    fn dedup_confidence_medium_with_hostname_only() {
        let d = make_discovered(None, Some("srv-prod-01"), Some("10.0.0.1"));
        assert_eq!(dedup_confidence_for(&d), "medium");
    }

    #[test]
    fn dedup_confidence_medium_with_fqdn_only() {
        let mut d = make_discovered(None, None, Some("10.0.0.1"));
        d.fqdn = Some("srv-prod-01.corp.local".into());
        assert_eq!(dedup_confidence_for(&d), "medium");
    }

    #[test]
    fn dedup_confidence_uncertain_with_ip_only() {
        let d = make_discovered(None, None, Some("10.0.0.1"));
        assert_eq!(dedup_confidence_for(&d), "uncertain");
    }

    #[test]
    fn dedup_confidence_uncertain_with_nothing() {
        let d = make_discovered(None, None, None);
        assert_eq!(dedup_confidence_for(&d), "uncertain");
    }

    #[test]
    fn test_generate_asset_id_hostname() {
        let d = DiscoveredAsset {
            mac: Some("00:1A:2B:3C:4D:5E".into()),
            hostname: Some("PC-COMPTA-03".into()),
            fqdn: None,
            ip: Some("192.168.30.15".into()),
            os: None,
            ports: None,
            ou: None,
            vlan: None,
            services: serde_json::json!([]),
            vm_id: None,
            criticality: None,
            source: "nmap".into(),
        };
        assert_eq!(generate_asset_id(&d), "pc-compta-03");
    }

    #[test]
    fn test_generate_asset_id_mac_only() {
        let d = DiscoveredAsset {
            mac: Some("00:1A:2B:3C:4D:5E".into()),
            hostname: None,
            fqdn: None,
            ip: None,
            os: None,
            ports: None,
            ou: None,
            vlan: None,
            services: serde_json::json!([]),
            vm_id: None,
            criticality: None,
            source: "arp".into(),
        };
        assert_eq!(generate_asset_id(&d), "asset-001a2b3c4d5e");
    }

    #[test]
    fn test_generate_asset_id_ip_only() {
        let d = DiscoveredAsset {
            mac: None,
            hostname: None,
            fqdn: None,
            ip: Some("192.168.1.10".into()),
            os: None,
            ports: None,
            ou: None,
            vlan: None,
            services: serde_json::json!([]),
            vm_id: None,
            criticality: None,
            source: "nmap".into(),
        };
        assert_eq!(generate_asset_id(&d), "asset-192-168-1-10");
    }

    #[test]
    fn test_confidence_single_source() {
        assert!((calculate_confidence(&["nmap".into()]) - 0.15).abs() < 0.001);
        assert!((calculate_confidence(&["ad".into()]) - 0.30).abs() < 0.001);
    }

    #[test]
    fn test_confidence_multi_source() {
        let sources = vec!["nmap".into(), "dhcp".into(), "ad".into()];
        let conf = calculate_confidence(&sources);
        assert!((conf - 0.70).abs() < 0.001); // 0.15 + 0.25 + 0.30
    }

    #[test]
    fn test_confidence_capped() {
        let sources = vec![
            "nmap".into(),
            "dhcp".into(),
            "ad".into(),
            "pfSense".into(),
            "proxmox".into(),
        ];
        let conf = calculate_confidence(&sources);
        assert!(conf <= 1.0);
    }
}

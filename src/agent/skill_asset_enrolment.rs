//! Phase 11f — Skill → Asset auto-enrolment.
//!
//! When the operator configures a connector skill (firewall, EDR, IAM,
//! SIEM…) ThreatClaw auto-creates the asset that *runs* that connector.
//! Without this hook the inventory is missing the very devices the
//! product is wired to, which is both confusing and breaks billing
//! (the OPNsense host should always be a declared asset).
//!
//! The enrolment is driven by a static catalogue mapping `skill_id` →
//! `AssetTemplate`. When the skill's config now carries a non-empty
//! `url` / `host` / `api_url` field and `enabled` is not explicitly
//! `"false"`, we upsert the corresponding asset with:
//!   * `inventory_status = "declared"` (manual presence is implied by
//!     the operator wiring the connector)
//!   * `source = "skill-{id}-config"` so it's distinguishable from
//!     auto-discovery rows
//!   * `category` / `subcategory` / `os` from the template
//!   * `criticality = "critical"` for everything that's part of the
//!     security plumbing (firewall, SIEM, DFIR…)
//!   * One IP extracted from the URL when it parses as such; otherwise
//!     left empty so a later discovery can fill it.
//!
//! Idempotent — re-runs of the hook upsert the same asset id, so the
//! operator typing a URL field by field generates one asset, not N.

use crate::db::Database;
use crate::db::threatclaw_store::NewAsset;
use serde_json::Value as JsonValue;

/// Static template used to render an asset from a skill's config blob.
struct AssetTemplate {
    /// Stable asset id. Same id across upserts → idempotent.
    id: &'static str,
    name: &'static str,
    category: &'static str,
    subcategory: &'static str,
    /// Best-known OS. May be `None` when the connector targets a
    /// platform-agnostic appliance (e.g. cloud APIs).
    os: Option<&'static str>,
    /// Default criticality. Always `critical` for connectors that touch
    /// the security perimeter — those *are* the security plumbing.
    criticality: &'static str,
    /// Tags to apply on the auto-enrolled asset. Always carries
    /// `enrolled` so the UI can show a "auto-enrolled from skill" hint
    /// without reading the source field.
    tags: &'static [&'static str],
}

/// Returns the asset template for a known connector skill, or `None`
/// when the skill should not produce an asset (analysis-only enrichers
/// like `skill-greynoise` query an external API; they aren't an asset
/// of the customer fleet).
fn template_for(skill_id: &str) -> Option<AssetTemplate> {
    match skill_id {
        // ── Firewalls ──────────────────────────────────────────
        "skill-opnsense" | "skill-opnsense-actions" => Some(AssetTemplate {
            id: "skill-opnsense-host",
            name: "OPNsense",
            category: "network",
            subcategory: "firewall",
            os: Some("FreeBSD (OPNsense)"),
            criticality: "critical",
            tags: &["enrolled", "firewall"],
        }),
        "skill-pfsense" => Some(AssetTemplate {
            id: "skill-pfsense-host",
            name: "pfSense",
            category: "network",
            subcategory: "firewall",
            os: Some("FreeBSD (pfSense)"),
            criticality: "critical",
            tags: &["enrolled", "firewall"],
        }),
        "skill-fortinet" | "skill-fortinet-actions" => Some(AssetTemplate {
            id: "skill-fortinet-host",
            name: "FortiGate",
            category: "network",
            subcategory: "firewall",
            os: Some("FortiOS"),
            criticality: "critical",
            tags: &["enrolled", "firewall"],
        }),
        "skill-mikrotik" => Some(AssetTemplate {
            id: "skill-mikrotik-host",
            name: "MikroTik",
            category: "network",
            subcategory: "router",
            os: Some("RouterOS"),
            criticality: "critical",
            tags: &["enrolled"],
        }),
        // ── SIEM / EDR ─────────────────────────────────────────
        "skill-wazuh" | "skill-wazuh-connector" | "skill-wazuh-alerts" => {
            Some(AssetTemplate {
                id: "skill-wazuh-host",
                name: "Wazuh",
                category: "server",
                subcategory: "siem",
                os: Some("Linux"),
                criticality: "critical",
                tags: &["enrolled", "siem"],
            })
        }
        "skill-elastic-siem" => Some(AssetTemplate {
            id: "skill-elastic-host",
            name: "Elastic SIEM",
            category: "server",
            subcategory: "siem",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "siem"],
        }),
        "skill-graylog" => Some(AssetTemplate {
            id: "skill-graylog-host",
            name: "Graylog",
            category: "server",
            subcategory: "siem",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "siem"],
        }),
        // ── DFIR ───────────────────────────────────────────────
        "skill-velociraptor" | "skill-velociraptor-actions" => Some(AssetTemplate {
            id: "skill-velociraptor-host",
            name: "Velociraptor",
            category: "server",
            subcategory: "dfir",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "dfir"],
        }),
        // ── IAM / Directory ────────────────────────────────────
        "skill-active-directory" => Some(AssetTemplate {
            id: "skill-active-directory-host",
            name: "Active Directory",
            category: "server",
            subcategory: "directory",
            os: Some("Windows Server"),
            criticality: "critical",
            tags: &["enrolled", "iam"],
        }),
        "skill-keycloak" => Some(AssetTemplate {
            id: "skill-keycloak-host",
            name: "Keycloak",
            category: "server",
            subcategory: "iam",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "iam"],
        }),
        "skill-authentik" => Some(AssetTemplate {
            id: "skill-authentik-host",
            name: "Authentik",
            category: "server",
            subcategory: "iam",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "iam"],
        }),
        // ── Misc supporting infra ──────────────────────────────
        "skill-glpi" | "skill-glpi-ticket" => Some(AssetTemplate {
            id: "skill-glpi-host",
            name: "GLPI",
            category: "server",
            subcategory: "ticketing",
            os: Some("Linux"),
            criticality: "high",
            tags: &["enrolled", "ticketing"],
        }),
        "skill-thehive" => Some(AssetTemplate {
            id: "skill-thehive-host",
            name: "TheHive",
            category: "server",
            subcategory: "soar",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "soar"],
        }),
        "skill-dfir-iris" => Some(AssetTemplate {
            id: "skill-iris-host",
            name: "DFIR-IRIS",
            category: "server",
            subcategory: "soar",
            os: Some("Linux"),
            criticality: "critical",
            tags: &["enrolled", "soar"],
        }),
        // ── Anything else: not an enrolment target ─────────────
        // Enrichers (greynoise, abuseipdb, virustotal, urlscan, …)
        // query external APIs and don't represent a customer asset.
        // Same for `skill-nmap-discovery` (action) and `skill-manual`.
        _ => None,
    }
}

/// Extract the host portion of a URL-ish string and return it as an IP
/// when it parses cleanly. Used to seed `ip_addresses` on the enrolled
/// asset; falls back to an empty list when the URL hostname is not an
/// IP literal (in which case `find_asset_by_hostname` will pick up the
/// FQDN at incident-resolution time).
fn url_to_ip(url: &str) -> Option<String> {
    let s = url.trim();
    if s.is_empty() {
        return None;
    }
    // Strip scheme.
    let after_scheme = s
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(s);
    // Strip path / query / fragment.
    let host_only = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip user info.
    let host_only = host_only
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(host_only);
    // Strip port.
    let host_only = host_only.split(':').next().unwrap_or(host_only);
    let trimmed = host_only.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Only emit if it parses as an IPv4/IPv6 literal.
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Same as [`url_to_ip`] but returns the hostname when it isn't a
/// literal IP — used to seed the asset's `hostname` field so the
/// dashboard can render `OPNsense (gw.corp.local)` instead of just
/// `OPNsense`.
fn url_to_hostname(url: &str) -> Option<String> {
    let s = url.trim();
    if s.is_empty() {
        return None;
    }
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let host_only = after_scheme.split(['/', '?', '#']).next().unwrap_or(after_scheme);
    let host_only = host_only.rsplit_once('@').map(|(_, h)| h).unwrap_or(host_only);
    let host_only = host_only.split(':').next().unwrap_or(host_only);
    let trimmed = host_only.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Find the URL-ish field in a skill config map. The skill catalogue
/// uses `url`, `host`, `api_url` interchangeably depending on the
/// vendor — pick whichever is set first.
fn pick_url(map: &std::collections::HashMap<String, String>) -> Option<&str> {
    for k in &["url", "api_url", "host"] {
        if let Some(v) = map.get(*k) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Phase 11f — main entry point. Called from `skill_config_set_handler`
/// after every config update. Best-effort: errors are logged by the
/// caller, not propagated to the operator (we don't want a typo in a
/// connector form to surface as a confusing 500).
pub async fn try_self_register(
    store: &dyn Database,
    skill_id: &str,
) -> Result<bool, String> {
    let Some(template) = template_for(skill_id) else {
        return Ok(false);
    };

    // Read the full key/value config for this skill.
    let kvs = store
        .get_skill_config(skill_id)
        .await
        .map_err(|e| e.to_string())?;
    let map: std::collections::HashMap<String, String> = kvs
        .into_iter()
        .map(|r| (r.key, r.value))
        .collect();

    // Skill explicitly disabled → don't enrol an asset for an
    // off connector. The asset may already exist from a previous
    // enrolment but we don't refresh it here.
    if map.get("enabled").map(|v| v == "false").unwrap_or(false) {
        return Ok(false);
    }

    let Some(url) = pick_url(&map) else {
        // Config incomplete (no host yet) — wait for a later update.
        return Ok(false);
    };

    let ip = url_to_ip(url);
    let hostname = url_to_hostname(url);

    let ip_addresses: Vec<String> = ip.into_iter().collect();

    let services_json = JsonValue::Array(vec![]);

    let asset = NewAsset {
        id: template.id.to_string(),
        name: template.name.to_string(),
        category: template.category.to_string(),
        subcategory: Some(template.subcategory.to_string()),
        role: None,
        criticality: template.criticality.to_string(),
        ip_addresses,
        mac_address: None,
        hostname,
        fqdn: None,
        url: Some(url.to_string()),
        os: template.os.map(|s| s.to_string()),
        mac_vendor: None,
        services: services_json,
        source: format!("{}-config", skill_id),
        owner: None,
        location: None,
        tags: template.tags.iter().map(|s| (*s).to_string()).collect(),
    };

    store
        .upsert_asset(&asset)
        .await
        .map_err(|e| e.to_string())?;

    tracing::info!(
        "skill-enrolment: upserted asset `{}` (skill: {})",
        template.id,
        skill_id
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_known_skills() {
        assert!(template_for("skill-opnsense").is_some());
        assert!(template_for("skill-velociraptor").is_some());
        assert!(template_for("skill-wazuh").is_some());
    }

    #[test]
    fn template_ignores_enrichers() {
        assert!(template_for("skill-greynoise").is_none());
        assert!(template_for("skill-abuseipdb").is_none());
        assert!(template_for("skill-virustotal").is_none());
        assert!(template_for("skill-nmap-discovery").is_none());
    }

    #[test]
    fn url_extracts_ip_literal() {
        assert_eq!(
            url_to_ip("https://10.77.0.1:8443/api"),
            Some("10.77.0.1".into())
        );
        assert_eq!(url_to_ip("10.77.0.1"), Some("10.77.0.1".into()));
        assert_eq!(url_to_ip("https://gw.corp.local:8443"), None);
    }

    #[test]
    fn url_extracts_hostname() {
        assert_eq!(
            url_to_hostname("https://gw.corp.local:8443/path"),
            Some("gw.corp.local".into())
        );
        assert_eq!(url_to_hostname("https://10.77.0.1"), None);
    }

    #[test]
    fn url_extracts_strips_user_info() {
        assert_eq!(
            url_to_hostname("https://admin:pass@gw.corp.local"),
            Some("gw.corp.local".into())
        );
    }

    #[test]
    fn pick_url_priority() {
        let mut m = std::collections::HashMap::new();
        m.insert("api_url".into(), "https://b".into());
        m.insert("url".into(), "https://a".into());
        m.insert("host".into(), "https://c".into());
        // url wins over api_url and host.
        assert_eq!(pick_url(&m), Some("https://a"));
    }
}

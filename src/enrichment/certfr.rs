//! CERT-FR RSS feed enrichment — daily sync of French security alerts.
//!
//! Parses RSS from https://www.cert.ssi.gouv.fr/
//! Stores alerts in PostgreSQL for correlation with findings.

use serde::{Deserialize, Serialize};

const CERTFR_AVI_RSS: &str = "https://www.cert.ssi.gouv.fr/avis/feed/";
const CERTFR_ALERTE_RSS: &str = "https://www.cert.ssi.gouv.fr/alerte/feed/";

/// A CERT-FR alert/advisory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertFrAlert {
    pub alert_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub published: String,
    pub link: String,
    pub cve_ids: Vec<String>,
}

/// Sync CERT-FR alerts from RSS feeds to the database.
/// Returns the number of new alerts synced.
pub async fn sync_certfr_alerts(store: &dyn crate::db::Database) -> Result<usize, String> {
    tracing::info!("CERT-FR: Starting RSS sync...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut total = 0;

    for (feed_url, default_severity) in &[(CERTFR_ALERTE_RSS, "critical"), (CERTFR_AVI_RSS, "high")]
    {
        let resp = client
            .get(*feed_url)
            .send()
            .await
            .map_err(|e| format!("CERT-FR RSS download failed: {e}"))?;

        if !resp.status().is_success() {
            tracing::warn!("CERT-FR RSS returned {}", resp.status());
            continue;
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| format!("CERT-FR RSS read error: {e}"))?;

        let count = parse_and_store_rss(&xml, default_severity, store).await?;
        total += count;
    }

    // Store sync metadata
    let meta = serde_json::json!({
        "last_sync": chrono::Utc::now().to_rfc3339(),
        "alert_count": total,
    });
    let _ = store
        .set_setting("_system", "certfr_sync_meta", &meta)
        .await;

    tracing::info!("CERT-FR: Synced {total} alerts");
    Ok(total)
}

/// Parse RSS XML and store alerts in DB.
async fn parse_and_store_rss(
    xml: &str,
    default_severity: &str,
    store: &dyn crate::db::Database,
) -> Result<usize, String> {
    let mut count = 0;

    // Simple XML parsing — extract <item> elements
    for item in xml.split("<item>").skip(1) {
        let title = extract_xml_tag(item, "title").unwrap_or_default();
        let link = extract_xml_tag(item, "link").unwrap_or_default();
        let description = extract_xml_tag(item, "description").unwrap_or_default();
        let pub_date = extract_xml_tag(item, "pubDate").unwrap_or_default();

        // Extract alert ID from link (e.g., CERTFR-2026-ALE-003)
        let alert_id = link
            .split('/')
            .filter(|s| s.starts_with("CERTFR-"))
            .next()
            .unwrap_or("")
            .to_string();

        if alert_id.is_empty() {
            continue;
        }

        // Check if already stored
        if let Ok(Some(_)) = store.get_setting("_certfr", &alert_id).await {
            continue; // Already have this alert
        }

        // Extract CVE IDs from description
        let cve_ids: Vec<String> = extract_cve_ids(&description)
            .into_iter()
            .chain(extract_cve_ids(&title))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Determine severity from title keywords
        let severity = if title.contains("[ALERTE]") || title.contains("ALERTE") {
            "critical"
        } else if title.contains("CRITICAL") || title.contains("critique") {
            "critical"
        } else {
            default_severity
        };

        let alert = serde_json::json!({
            "alert_id": alert_id,
            "title": clean_html(&title),
            "description": clean_html(&description).chars().take(500).collect::<String>(),
            "severity": severity,
            "published": pub_date,
            "link": link,
            "cve_ids": cve_ids,
            "fetched_at": chrono::Utc::now().to_rfc3339(),
        });

        if let Err(e) = store.set_setting("_certfr", &alert_id, &alert).await {
            tracing::warn!("Failed to store CERT-FR alert {alert_id}: {e}");
            continue;
        }
        count += 1;
    }

    Ok(count)
}

/// Extract content between XML tags.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

/// Extract CVE IDs from text using regex-like matching.
fn extract_cve_ids(text: &str) -> Vec<String> {
    let mut cves = Vec::new();
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
        if clean.starts_with("CVE-") && clean.len() >= 13 {
            cves.push(clean.to_string());
        }
    }
    // Also scan for CVE pattern in continuous text (char-boundary safe)
    for (i, _) in text.char_indices() {
        if text[i..].starts_with("CVE-") {
            let end = text[i..]
                .find(|c: char| !c.is_alphanumeric() && c != '-')
                .map(|p| i + p)
                .unwrap_or(text.len());
            let candidate = &text[i..end];
            if candidate.len() >= 13 && !cves.contains(&candidate.to_string()) {
                cves.push(candidate.to_string());
            }
        }
    }
    cves
}

/// Strip basic HTML tags from text.
fn clean_html(text: &str) -> String {
    // Remove CDATA wrappers
    let text = text.replace("<![CDATA[", "").replace("]]>", "");
    // Remove HTML tags
    let mut result = String::new();
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    result.trim().to_string()
}

/// Get last sync metadata.
pub async fn get_sync_meta(store: &dyn crate::db::Database) -> Option<serde_json::Value> {
    store
        .get_setting("_system", "certfr_sync_meta")
        .await
        .ok()?
}

/// Get recent alerts (last N).
pub async fn get_recent_alerts(store: &dyn crate::db::Database, limit: usize) -> Vec<CertFrAlert> {
    let settings = store.list_settings("_certfr").await.unwrap_or_default();
    let mut alerts: Vec<CertFrAlert> = settings
        .iter()
        .filter_map(|s| serde_json::from_value(s.value.clone()).ok())
        .collect();
    alerts.sort_by(|a, b| b.published.cmp(&a.published));
    alerts.truncate(limit);
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cve_ids() {
        let text = "This advisory covers CVE-2024-12345 and CVE-2024-67890.";
        let cves = extract_cve_ids(text);
        assert!(cves.contains(&"CVE-2024-12345".to_string()));
        assert!(cves.contains(&"CVE-2024-67890".to_string()));
    }

    #[test]
    fn test_clean_html() {
        assert_eq!(clean_html("<p>Hello <b>world</b></p>"), "Hello world");
        assert_eq!(clean_html("<![CDATA[test]]>"), "test");
    }

    #[test]
    fn test_extract_xml_tag() {
        let xml = "<title>My Title</title><link>http://example.com</link>";
        assert_eq!(extract_xml_tag(xml, "title"), Some("My Title".to_string()));
        assert_eq!(
            extract_xml_tag(xml, "link"),
            Some("http://example.com".to_string())
        );
    }
}

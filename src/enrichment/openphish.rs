//! OpenPhish — phishing URL feed.
//! Free feed: ~500 URLs, no API key. Updated every 6 hours.

const FEED_URL: &str = "https://openphish.com/feed.txt";

/// Sync OpenPhish feed to DB. Returns number of URLs synced.
pub async fn sync_feed(store: &dyn crate::db::Database) -> Result<usize, String> {
    tracing::info!("OpenPhish: Starting sync...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build().map_err(|e| format!("HTTP: {e}"))?;

    let resp = client.get(FEED_URL).send().await.map_err(|e| format!("OpenPhish: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("OpenPhish HTTP {}", resp.status()));
    }

    let text = resp.text().await.map_err(|e| format!("Read: {e}"))?;
    let urls: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty() && l.starts_with("http")).collect();

    // Store as a single blob (small enough)
    let _ = store.set_setting("_enrichment", "openphish_urls", &serde_json::json!({
        "urls": urls,
        "count": urls.len(),
        "synced_at": chrono::Utc::now().to_rfc3339(),
    })).await;

    tracing::info!("OpenPhish: Synced {} URLs", urls.len());
    Ok(urls.len())
}

/// Check if a URL is in the OpenPhish feed.
pub async fn is_phishing(store: &dyn crate::db::Database, url: &str) -> bool {
    if let Ok(Some(data)) = store.get_setting("_enrichment", "openphish_urls").await {
        if let Some(urls) = data["urls"].as_array() {
            return urls.iter().any(|u| u.as_str() == Some(url));
        }
    }
    false
}

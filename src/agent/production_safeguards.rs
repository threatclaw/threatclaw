//! Production Safeguards — prevents the Intelligence Engine from
//! creating duplicate findings, spamming notifications, or overloading
//! external enrichment APIs.
//!
//! These are the guardrails that make ThreatClaw production-ready.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use serde_json::json;
use crate::db::Database;

// ══════════════════════════════════════════════════════════
// 1. FINDING DEDUPLICATION
// Prevents creating the same finding multiple times per cycle.
// ══════════════════════════════════════════════════════════

/// Check if a similar finding already exists (same title pattern + asset + last 24h).
/// Returns true if duplicate found (should NOT create a new finding).
pub async fn is_duplicate_finding(
    store: &dyn Database,
    title_pattern: &str,
    asset: Option<&str>,
) -> bool {
    use crate::db::threatclaw_store::ThreatClawStore;

    let findings = store.list_findings(None, Some("open"), None, 100, 0).await.unwrap_or_default();

    for f in &findings {
        // Check title similarity (contains the same key phrases)
        let title_match = f.title.contains(title_pattern) ||
            title_pattern.contains(&f.title) ||
            (f.title.len() > 20 && title_pattern.len() > 20 &&
             f.title[..20] == title_pattern[..title_pattern.len().min(20)]);

        // Check asset match
        let asset_match = match (asset, f.asset.as_deref()) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        };

        // Check if recent (last 24h)
        if let Ok(detected) = chrono::DateTime::parse_from_rfc3339(&f.detected_at) {
            let age = chrono::Utc::now() - detected.with_timezone(&chrono::Utc);
            if age < chrono::Duration::hours(24) && title_match && asset_match {
                return true; // Duplicate
            }
        }
    }

    false
}

// ══════════════════════════════════════════════════════════
// 2. NOTIFICATION COOLDOWN
// Prevents spamming the RSSI with the same alert every 5 min.
// ══════════════════════════════════════════════════════════

/// Check if we should send a notification or if we're in cooldown.
/// Returns true if notification should be SENT.
pub async fn should_notify(
    store: &dyn Database,
    level: &str,
) -> bool {
    let key = "last_notification";

    if let Ok(Some(last)) = store.get_setting("_system", key).await {
        let last_level = last["level"].as_str().unwrap_or("");
        let last_time = last["time"].as_str().unwrap_or("");
        let last_score = last["score"].as_f64().unwrap_or(0.0);

        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(last_time) {
            let elapsed = chrono::Utc::now() - t.with_timezone(&chrono::Utc);

            // Critical: cooldown 15 min (if same level + score hasn't changed significantly)
            if level == "Critical" && last_level == "Critical" && elapsed < chrono::Duration::minutes(15) {
                tracing::debug!("SAFEGUARD: Critical notification cooldown ({:.0} min ago)", elapsed.num_minutes());
                return false;
            }

            // Alert: cooldown 30 min
            if level == "Alert" && last_level == "Alert" && elapsed < chrono::Duration::minutes(30) {
                tracing::debug!("SAFEGUARD: Alert notification cooldown ({:.0} min ago)", elapsed.num_minutes());
                return false;
            }

            // Digest: cooldown 12h
            if level == "Digest" && last_level == "Digest" && elapsed < chrono::Duration::hours(12) {
                tracing::debug!("SAFEGUARD: Digest notification cooldown ({:.0}h ago)", elapsed.num_hours());
                return false;
            }

            // If level escalated (e.g., Alert → Critical), always send
            let level_order = |l: &str| match l {
                "Critical" => 3, "Alert" => 2, "Digest" => 1, _ => 0
            };
            if level_order(level) > level_order(last_level) {
                tracing::info!("SAFEGUARD: Level escalated {} → {} — sending", last_level, level);
                return true;
            }
        }
    }

    true // First notification or expired cooldown
}

/// Record that a notification was sent.
pub async fn record_notification_sent(
    store: &dyn Database,
    level: &str,
    score: f64,
) {
    let _ = store.set_setting("_system", "last_notification", &json!({
        "level": level,
        "score": score,
        "time": chrono::Utc::now().to_rfc3339(),
    })).await;
}

// ══════════════════════════════════════════════════════════
// 3. IOC CACHE
// Caches enrichment API results to avoid re-querying the same
// IP/URL/hash every 5-minute cycle.
// ══════════════════════════════════════════════════════════

/// Check if an IoC enrichment result is cached (< 24h old).
pub async fn get_cached_ioc(
    store: &dyn Database,
    ioc_type: &str,
    ioc_value: &str,
) -> Option<serde_json::Value> {
    let key = format!("{}_{}", ioc_type, ioc_value.replace('.', "_").replace(':', "_"));

    if let Ok(Some(cached)) = store.get_setting("_ioc_cache", &key).await {
        if let Some(time) = cached["cached_at"].as_str() {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(time) {
                let age = chrono::Utc::now() - t.with_timezone(&chrono::Utc);
                if age < chrono::Duration::hours(24) {
                    return Some(cached["result"].clone());
                }
            }
        }
    }

    None
}

/// Cache an IoC enrichment result.
pub async fn cache_ioc(
    store: &dyn Database,
    ioc_type: &str,
    ioc_value: &str,
    result: &serde_json::Value,
) {
    let key = format!("{}_{}", ioc_type, ioc_value.replace('.', "_").replace(':', "_"));
    let _ = store.set_setting("_ioc_cache", &key, &json!({
        "result": result,
        "cached_at": chrono::Utc::now().to_rfc3339(),
    })).await;
}

// ══════════════════════════════════════════════════════════
// 4. ENRICHMENT RATE LIMITER
// Limits external API calls per cycle to prevent timeouts
// and API bans.
// ══════════════════════════════════════════════════════════

/// Rate limiter state for a single cycle.
pub struct CycleRateLimiter {
    pub max_lookups: usize,
    pub lookups_done: usize,
    pub ips_seen: HashSet<String>,
    pub urls_seen: HashSet<String>,
    pub hashes_seen: HashSet<String>,
}

impl CycleRateLimiter {
    pub fn new(max_lookups: usize) -> Self {
        Self {
            max_lookups,
            lookups_done: 0,
            ips_seen: HashSet::new(),
            urls_seen: HashSet::new(),
            hashes_seen: HashSet::new(),
        }
    }

    /// Check if we can do another lookup (under rate limit).
    pub fn can_lookup(&self) -> bool {
        self.lookups_done < self.max_lookups
    }

    /// Record a lookup was performed.
    pub fn record_lookup(&mut self) {
        self.lookups_done += 1;
    }

    /// Check if this IP was already looked up this cycle.
    pub fn ip_already_seen(&mut self, ip: &str) -> bool {
        !self.ips_seen.insert(ip.to_string())
    }

    /// Check if this URL was already looked up this cycle.
    pub fn url_already_seen(&mut self, url: &str) -> bool {
        !self.urls_seen.insert(url.to_string())
    }

    /// Check if this hash was already looked up this cycle.
    pub fn hash_already_seen(&mut self, hash: &str) -> bool {
        !self.hashes_seen.insert(hash.to_string())
    }
}

// ══════════════════════════════════════════════════════════
// 5. LLM RESPONSE VALIDATION
// Strict validation of LLM JSON output before creating findings.
// ══════════════════════════════════════════════════════════

const VALID_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/// Validate and sanitize a severity string from LLM output.
/// Returns a valid severity or None if unrecoverable.
pub fn validate_severity(raw: &str) -> Option<String> {
    let upper = raw.trim().to_uppercase();

    // Exact match
    if VALID_SEVERITIES.contains(&upper.as_str()) {
        return Some(upper);
    }

    // Contains a valid severity (e.g., "HIGH/CRITICAL" → take the highest)
    for sev in VALID_SEVERITIES {
        if upper.contains(sev) {
            return Some(sev.to_string());
        }
    }

    // Common misspellings / alternatives
    if upper.contains("CRIT") { return Some("CRITICAL".into()); }
    if upper.contains("HAUT") || upper.contains("ÉLEVÉ") { return Some("HIGH".into()); }
    if upper.contains("MOYEN") { return Some("MEDIUM".into()); }
    if upper.contains("BAS") || upper.contains("FAIBLE") { return Some("LOW".into()); }

    tracing::warn!("SAFEGUARD: Invalid severity '{}' — cannot recover", raw);
    None
}

/// Validate confidence value (0.0 - 1.0).
/// Returns sanitized value or default.
pub fn validate_confidence(raw: f64) -> f64 {
    if raw >= 0.0 && raw <= 1.0 {
        raw
    } else if raw > 1.0 && raw <= 100.0 {
        raw / 100.0 // LLM returned percentage instead of decimal
    } else {
        tracing::warn!("SAFEGUARD: Invalid confidence {} — using 0.5 default", raw);
        0.5
    }
}

// ── V3: Delta-based re-notification for investigation verdicts ──

use crate::agent::verdict::InvestigationVerdict;

/// Check if a new verdict justifies re-notification (delta-based, not time-based).
///
/// Returns true if the RSSI should be notified again. Unlike the legacy `should_notify()`
/// which uses cooldown timers, this checks whether anything has actually changed.
pub async fn should_renotify_verdict(
    store: &dyn Database,
    asset: &str,
    new_verdict: &InvestigationVerdict,
) -> bool {
    let key = format!("last_verdict:{asset}");

    match store.get_setting("_system", &key).await {
        Ok(Some(prev)) => {
            let prev_severity = prev.get("severity").and_then(|v| v.as_str()).unwrap_or("");
            let prev_confidence = prev.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let prev_verdict_type = prev.get("verdict_type").and_then(|v| v.as_str()).unwrap_or("");

            let severity_order = |s: &str| match s {
                "CRITICAL" => 4,
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0,
            };

            // Re-notify if:
            // 1. Severity escalated
            severity_order(new_verdict.severity()) > severity_order(prev_severity)
            // 2. Verdict type changed (e.g. inconclusive → confirmed)
            || new_verdict.verdict_type() != prev_verdict_type
            // 3. Confidence changed significantly (> 20 points)
            || (new_verdict.confidence() - prev_confidence).abs() > 0.20
        }
        Ok(None) => true, // First notification for this asset
        Err(_) => true,    // DB error → notify to be safe
    }
}

/// Record the last verdict for an asset (for delta checking).
pub async fn record_verdict_sent(
    store: &dyn Database,
    asset: &str,
    verdict: &InvestigationVerdict,
) {
    let key = format!("last_verdict:{asset}");
    let _ = store
        .set_setting(
            "_system",
            &key,
            &serde_json::json!({
                "severity": verdict.severity(),
                "confidence": verdict.confidence(),
                "verdict_type": verdict.verdict_type(),
                "time": chrono::Utc::now().to_rfc3339(),
            }),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_severity() {
        assert_eq!(validate_severity("CRITICAL"), Some("CRITICAL".into()));
        assert_eq!(validate_severity("high"), Some("HIGH".into()));
        assert_eq!(validate_severity("LOW|MEDIUM|HIGH|CRITICAL"), Some("CRITICAL".into()));
        assert_eq!(validate_severity("critique"), Some("CRITICAL".into()));
        assert_eq!(validate_severity("élevé"), Some("HIGH".into()));
        assert_eq!(validate_severity("garbage"), None);
    }

    #[test]
    fn test_validate_confidence() {
        assert_eq!(validate_confidence(0.85), 0.85);
        assert_eq!(validate_confidence(85.0), 0.85); // Percentage → decimal
        assert_eq!(validate_confidence(-1.0), 0.5); // Invalid → default
        assert_eq!(validate_confidence(150.0), 0.5); // Invalid → default
    }
}

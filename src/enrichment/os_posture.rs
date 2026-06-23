//! OS posture — flags end-of-life / soon-EOL operating systems using endoflife.date.
//! Best-effort: any failure logs and yields nothing; never panics, never blocks.

/// First run of digits in `s` (e.g. "debian 12" → "12", "rhel 9.2" → "9").
fn first_int(s: &str) -> Option<String> {
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            break;
        }
    }
    (!cur.is_empty()).then_some(cur)
}

/// First `NN.NN`-style token (e.g. "ubuntu 22.04.3" → "22.04", "alpine v3.18" → "3.18").
fn first_dotted2(s: &str) -> Option<String> {
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() || (ch == '.' && !cur.is_empty()) {
            cur.push(ch);
        } else if !cur.is_empty() {
            break;
        }
    }
    let parts: Vec<&str> = cur.split('.').filter(|p| !p.is_empty()).collect();
    (parts.len() >= 2).then(|| format!("{}.{}", parts[0], parts[1]))
}

/// Map an osquery-derived `asset.os` to an endoflife.date `(product, cycle)`.
/// `None` when not confidently mappable, so no EOL finding is produced.
pub fn parse_os(os: &str) -> Option<(&'static str, String)> {
    let s = os.to_lowercase();
    if s.contains("windows server") {
        if s.contains("2012 r2") {
            return Some(("windows-server", "2012-r2".into()));
        }
        for year in ["2025", "2022", "2019", "2016", "2012"] {
            if s.contains(year) {
                return Some(("windows-server", year.to_string()));
            }
        }
        return None;
    }
    if s.contains("windows") {
        return None; // client Windows EOL deferred to a later pass
    }
    if s.contains("debian") {
        return first_int(&s).map(|v| ("debian", v));
    }
    if s.contains("ubuntu") {
        return first_dotted2(&s).map(|v| ("ubuntu", v));
    }
    if s.contains("alpine") {
        return first_dotted2(&s).map(|v| ("alpine", v));
    }
    if s.contains("red hat") || s.contains("rhel") {
        return first_int(&s).map(|v| ("rhel", v));
    }
    if s.contains("almalinux") || s.contains("alma") {
        return first_int(&s).map(|v| ("almalinux", v));
    }
    if s.contains("rocky") {
        return first_int(&s).map(|v| ("rocky", v));
    }
    if s.contains("centos") {
        return first_int(&s).map(|v| ("centos", v));
    }
    None
}

/// Outcome of an EOL check. Carries the EOL date string for the finding text.
#[derive(Debug, Clone, PartialEq)]
pub enum EolStatus {
    Eol(String),
    Approaching(String),
}

/// Interpret an endoflife.date `eol` field (ISO date string, or a bool) against
/// `today`. Past/true → `Eol`; within 90 days → `Approaching`; else `None`.
pub fn eol_assessment(eol: &serde_json::Value, today: chrono::NaiveDate) -> Option<EolStatus> {
    match eol {
        serde_json::Value::Bool(true) => Some(EolStatus::Eol("past".into())),
        serde_json::Value::String(s) => {
            let date = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
            if date <= today {
                Some(EolStatus::Eol(s.clone()))
            } else if (date - today).num_days() <= 90 {
                Some(EolStatus::Approaching(s.clone()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Flatten an endoflife.date product feed (array of `{cycle, eol, ...}`) into
/// `cycle → eol`.
pub fn parse_eol_feed(
    json: &serde_json::Value,
) -> std::collections::HashMap<String, serde_json::Value> {
    let mut map = std::collections::HashMap::new();
    if let Some(arr) = json.as_array() {
        for row in arr {
            if let Some(cycle) = row["cycle"].as_str() {
                map.insert(cycle.to_string(), row["eol"].clone());
            }
        }
    }
    map
}

/// Construct the finding for an EOL status. HIGH when past EOL, MEDIUM when EOL
/// is approaching. The OS string is kept verbatim for the operator.
pub fn build_eol_finding(
    asset_name: &str,
    os: &str,
    product: &str,
    cycle: &str,
    status: &EolStatus,
) -> crate::db::threatclaw_store::NewFinding {
    let (severity, signal, i18n_key, date, title, desc) = match status {
        EolStatus::Eol(date) => (
            "HIGH",
            "eol",
            "finding.os_posture.eol",
            date.clone(),
            format!("{os} — système en fin de vie (EOL)"),
            format!(
                "{asset_name} fait tourner {os}, qui ne reçoit plus de mises à jour de sécurité (EOL : {date}). Migrer vers une version supportée."
            ),
        ),
        EolStatus::Approaching(date) => (
            "MEDIUM",
            "eol-approaching",
            "finding.os_posture.eol_approaching",
            date.clone(),
            format!("{os} — fin de vie imminente"),
            format!(
                "{asset_name} fait tourner {os}, dont le support de sécurité se termine le {date} (< 90 jours). Planifier la migration."
            ),
        ),
    };
    crate::db::threatclaw_store::NewFinding {
        skill_id: "os-posture".into(),
        title,
        description: Some(desc),
        severity: severity.into(),
        category: Some("os-posture".into()),
        asset: Some(asset_name.to_string()),
        source: Some("OS posture".into()),
        metadata: Some(serde_json::json!({
            "signal": signal,
            "os": os,
            "product": product,
            "cycle": cycle,
            "eol_date": date,
            "detection": "os-posture-eol",
            "mitre": ["T1190"],
            "i18n": crate::enrichment::finding_i18n::i18n(
                i18n_key,
                serde_json::json!({ "os": os, "date": date, "asset": asset_name }),
            ),
        })),
    }
}

/// endoflife.date products we map assets to.
const EOL_PRODUCTS: &[&str] = &[
    "windows-server",
    "debian",
    "ubuntu",
    "rhel",
    "almalinux",
    "rocky",
    "centos",
    "alpine",
    "fedora",
    "sles",
];

/// Fetch every product feed once and flatten to `(product, cycle) → eol`. Any
/// product that fails to fetch is skipped (logged); empty map = no findings.
pub async fn fetch_eol_map() -> std::collections::HashMap<(String, String), serde_json::Value> {
    let mut map = std::collections::HashMap::new();
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("OS-POSTURE: HTTP client build failed ({e})");
            return map;
        }
    };
    for product in EOL_PRODUCTS {
        let url = format!("https://endoflife.date/api/{product}.json");
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        for (cycle, eol) in parse_eol_feed(&json) {
                            map.insert((product.to_string(), cycle), eol);
                        }
                    }
                    Err(e) => tracing::warn!("OS-POSTURE: {product} JSON failed ({e})"),
                }
            }
            Ok(resp) => tracing::warn!("OS-POSTURE: {product} returned {}", resp.status()),
            Err(e) => tracing::warn!("OS-POSTURE: {product} fetch failed ({e})"),
        }
    }
    map
}

/// Daily EOL pass over all active assets. Best-effort; returns findings created.
pub async fn scan_all_assets_eol(store: std::sync::Arc<dyn crate::db::Database>) -> usize {
    let eol_map = fetch_eol_map().await;
    if eol_map.is_empty() {
        return 0;
    }
    let today = chrono::Utc::now().date_naive();
    let assets = store
        .list_assets(None, Some("active"), 500, 0)
        .await
        .unwrap_or_default();

    let mut created = 0usize;
    for asset in &assets {
        let os = match asset.os.as_deref() {
            Some(o) if !o.trim().is_empty() => o,
            _ => continue,
        };
        let Some((product, cycle)) = parse_os(os) else {
            continue;
        };
        let Some(eol) = eol_map.get(&(product.to_string(), cycle.clone())) else {
            continue;
        };
        let Some(status) = eol_assessment(eol, today) else {
            continue;
        };

        // Dedup: skip if this asset already has an os-posture EOL finding for this product.
        let existing = store
            .list_findings(None, None, Some(&asset.name), 1000, 0)
            .await
            .unwrap_or_default();
        let already = existing.iter().any(|f| {
            f.category.as_deref() == Some("os-posture")
                && f.metadata.get("product").and_then(|p| p.as_str()) == Some(product)
        });
        if already {
            continue;
        }

        let finding = build_eol_finding(&asset.name, os, product, &cycle, &status);
        let _ = store.insert_finding(&finding).await;
        created += 1;
    }
    if created > 0 {
        tracing::info!(
            "OS-POSTURE: EOL scan complete — {created} findings across {} assets",
            assets.len()
        );
    }
    created
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn eol_assessment_classifies_dates() {
        let today = d("2026-06-23");
        assert!(matches!(
            eol_assessment(&serde_json::json!("2024-08-14"), today),
            Some(EolStatus::Eol(_))
        ));
        assert!(matches!(
            eol_assessment(&serde_json::json!("2026-07-11"), today),
            Some(EolStatus::Approaching(_))
        ));
        assert_eq!(
            eol_assessment(&serde_json::json!("2030-01-01"), today),
            None
        );
        assert!(matches!(
            eol_assessment(&serde_json::json!(true), today),
            Some(EolStatus::Eol(_))
        ));
        assert_eq!(eol_assessment(&serde_json::json!(false), today), None);
        assert_eq!(eol_assessment(&serde_json::Value::Null, today), None);
    }

    #[test]
    fn parse_eol_feed_maps_cycle_to_eol() {
        let feed = serde_json::json!([
            {"cycle": "12", "eol": "2026-07-11", "latest": "12.5"},
            {"cycle": "11", "eol": "2024-08-14"},
            {"cycle": "10", "eol": true}
        ]);
        let m = parse_eol_feed(&feed);
        assert_eq!(m.get("12"), Some(&serde_json::json!("2026-07-11")));
        assert_eq!(m.get("10"), Some(&serde_json::json!(true)));
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn build_eol_finding_sets_category_and_severity() {
        let f = build_eol_finding(
            "srv-old",
            "Debian GNU/Linux 11",
            "debian",
            "11",
            &EolStatus::Eol("2024-08-14".into()),
        );
        assert_eq!(f.category.as_deref(), Some("os-posture"));
        assert_eq!(f.source.as_deref(), Some("OS posture"));
        assert_eq!(f.severity, "HIGH");
        assert_eq!(f.metadata.as_ref().unwrap()["signal"], "eol");
        assert_eq!(f.metadata.as_ref().unwrap()["os"], "Debian GNU/Linux 11");

        let a = build_eol_finding(
            "srv-soon",
            "Debian GNU/Linux 12",
            "debian",
            "12",
            &EolStatus::Approaching("2026-07-11".into()),
        );
        assert_eq!(a.severity, "MEDIUM");
        assert_eq!(a.metadata.as_ref().unwrap()["signal"], "eol-approaching");
    }

    #[test]
    fn finding_carries_i18n_key_and_params() {
        let f = build_eol_finding(
            "srv",
            "Debian GNU/Linux 12",
            "debian",
            "12",
            &EolStatus::Approaching("2026-07-11".into()),
        );
        let i = &f.metadata.as_ref().unwrap()["i18n"];
        assert_eq!(i["key"], "finding.os_posture.eol_approaching");
        assert_eq!(i["params"]["os"], "Debian GNU/Linux 12");
        assert_eq!(i["params"]["date"], "2026-07-11");
        assert_eq!(i["params"]["asset"], "srv");

        let e = build_eol_finding(
            "srv",
            "Debian GNU/Linux 11",
            "debian",
            "11",
            &EolStatus::Eol("2024-08-14".into()),
        );
        assert_eq!(
            e.metadata.as_ref().unwrap()["i18n"]["key"],
            "finding.os_posture.eol"
        );
    }

    #[test]
    fn parses_windows_server_and_linux() {
        assert_eq!(
            parse_os("Microsoft Windows Server 2019 10.0.17763"),
            Some(("windows-server", "2019".into()))
        );
        assert_eq!(
            parse_os("Microsoft Windows Server 2012 R2"),
            Some(("windows-server", "2012-r2".into()))
        );
        assert_eq!(
            parse_os("Debian GNU/Linux 12 (bookworm)"),
            Some(("debian", "12".into()))
        );
        assert_eq!(
            parse_os("Ubuntu 22.04.3 LTS"),
            Some(("ubuntu", "22.04".into()))
        );
        assert_eq!(
            parse_os("Red Hat Enterprise Linux 9.2"),
            Some(("rhel", "9".into()))
        );
        assert_eq!(
            parse_os("Alpine Linux v3.18"),
            Some(("alpine", "3.18".into()))
        );
    }

    #[test]
    fn unknown_os_is_none() {
        assert_eq!(parse_os("Microsoft Windows 11 Pro"), None); // client OS deferred
        assert_eq!(parse_os("Stormshield NS-BSD"), None);
        assert_eq!(parse_os(""), None);
    }
}

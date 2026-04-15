//! Vulnerability-Lookup (CIRCL) — CVE enrichment from 40+ sources.
//! Public API, no authentication required for reads.
//! Provides: multi-source CVE data, sightings (Metasploit/Nuclei/ExploitDB),
//! EPSS history, detection rules (Sigma/YARA), EU KEV catalog.
//! https://vulnerability.circl.lu/

use serde::{Deserialize, Serialize};

const BASE_URL: &str = "https://vulnerability.circl.lu/api";

// ── Response types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnLookupResult {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub cvss: Option<f64>,
    pub severity: Option<String>,
    pub published: Option<String>,
    pub sources: Vec<String>,
    pub sightings: Vec<Sighting>,
    pub detection_rules: Vec<DetectionRule>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sighting {
    pub source: String, // "metasploit", "nuclei", "exploitdb", "misp", "shadowserver"
    pub sighting_type: String, // "seen", "exploited", "patched"
    pub description: Option<String>,
    pub date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub rule_type: String, // "sigma", "yara", "suricata"
    pub name: String,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssHistory {
    pub cve_id: String,
    pub current_score: f64,
    pub percentile: Option<f64>,
    pub history: Vec<EpssPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssPoint {
    pub date: String,
    pub score: f64,
}

// ── Client helper ──

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("ThreatClaw/2.2")
        .build()
        .map_err(|e| format!("HTTP client: {e}"))
}

// ── Core lookup: CVE details from 40+ sources ──

pub async fn lookup_cve(cve_id: &str) -> Result<VulnLookupResult, String> {
    let c = client()?;
    let url = format!("{}/vulnerability/{}", BASE_URL, cve_id);
    let resp = c
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("VulnLookup: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("VulnLookup API returned {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    // Extract from CVE 5.x format
    let containers = &data["containers"]["cna"];
    let title = containers["title"]
        .as_str()
        .or_else(|| data["cveMetadata"]["cveId"].as_str())
        .unwrap_or(cve_id)
        .to_string();

    let description = containers["descriptions"]
        .as_array()
        .and_then(|descs| {
            descs
                .iter()
                .find(|d| d["lang"].as_str() == Some("en") || d["lang"].as_str() == Some("fr"))
                .or_else(|| descs.first())
        })
        .and_then(|d| d["value"].as_str())
        .unwrap_or("")
        .to_string();

    // CVSS from metrics
    let cvss = containers["metrics"].as_array().and_then(|metrics| {
        metrics.iter().find_map(|m| {
            m["cvssV3_1"]["baseScore"]
                .as_f64()
                .or_else(|| m["cvssV3_0"]["baseScore"].as_f64())
                .or_else(|| m["cvssV4_0"]["baseScore"].as_f64())
        })
    });

    let severity = cvss.map(|s| {
        {
            if s >= 9.0 {
                "CRITICAL"
            } else if s >= 7.0 {
                "HIGH"
            } else if s >= 4.0 {
                "MEDIUM"
            } else {
                "LOW"
            }
        }
        .to_string()
    });

    let published = data["cveMetadata"]["datePublished"]
        .as_str()
        .or_else(|| data["cveMetadata"]["dateReserved"].as_str())
        .map(String::from);

    // Sources that contributed data
    let sources = data["containers"]
        .as_object()
        .map(|obj| obj.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    let references = containers["references"]
        .as_array()
        .map(|refs| {
            refs.iter()
                .filter_map(|r| r["url"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Sightings fetched separately
    let sightings = fetch_sightings(cve_id).await.unwrap_or_default();
    let detection_rules = fetch_detection_rules(cve_id).await.unwrap_or_default();

    Ok(VulnLookupResult {
        cve_id: cve_id.to_string(),
        title,
        description,
        cvss,
        severity,
        published,
        sources,
        sightings,
        detection_rules,
        references,
    })
}

// ── Sightings: exploit availability (Metasploit, Nuclei, ExploitDB, MISP...) ──

pub async fn fetch_sightings(cve_id: &str) -> Result<Vec<Sighting>, String> {
    let c = client()?;
    let url = format!("{}/sighting/?vuln_id={}", BASE_URL, cve_id);
    let resp = c
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Sightings: {e}"))?;

    if !resp.status().is_success() {
        return Ok(vec![]);
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    // Response can be paginated: { "metadata": {...}, "data": [...] } or a direct array
    let items = data["data"].as_array().or_else(|| data.as_array());

    let sightings = items
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    Some(Sighting {
                        source: s["source"].as_str()?.to_string(),
                        sighting_type: s["type"].as_str().unwrap_or("seen").to_string(),
                        description: s["description"].as_str().map(String::from),
                        date: s["creation_timestamp"]
                            .as_str()
                            .or_else(|| s["date"].as_str())
                            .map(String::from),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(sightings)
}

// ── Detection rules: Sigma/YARA per CVE ──

pub async fn fetch_detection_rules(cve_id: &str) -> Result<Vec<DetectionRule>, String> {
    let c = client()?;
    let url = format!(
        "{}/rulezet/search_rules_by_vulnerabilities/{}",
        BASE_URL, cve_id
    );
    let resp = c
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Rules: {e}"))?;

    if !resp.status().is_success() {
        return Ok(vec![]);
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    let items = data["data"].as_array().or_else(|| data.as_array());

    let rules = items
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(DetectionRule {
                        rule_type: r["type"].as_str().unwrap_or("sigma").to_string(),
                        name: r["name"]
                            .as_str()
                            .or_else(|| r["title"].as_str())?
                            .to_string(),
                        source: r["source"].as_str().map(String::from),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(rules)
}

// ── EPSS with history ──

pub async fn fetch_epss(cve_id: &str) -> Result<EpssHistory, String> {
    let c = client()?;
    let url = format!("{}/epss/{}", BASE_URL, cve_id);
    let resp = c.get(&url).send().await.map_err(|e| format!("EPSS: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("EPSS API returned {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    let current_score = data["epss"]
        .as_f64()
        .or_else(|| data["score"].as_f64())
        .unwrap_or(0.0);

    let percentile = data["percentile"].as_f64();

    let history = data["history"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(EpssPoint {
                        date: p["date"].as_str()?.to_string(),
                        score: p["epss"].as_f64().or_else(|| p["score"].as_f64())?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(EpssHistory {
        cve_id: cve_id.to_string(),
        current_score,
        percentile,
        history,
    })
}

// ── Convenience: check if exploit exists (for Priority Score integration) ──

pub async fn has_public_exploit(cve_id: &str) -> bool {
    match fetch_sightings(cve_id).await {
        Ok(sightings) => sightings.iter().any(|s| {
            s.source.contains("metasploit")
                || s.source.contains("nuclei")
                || s.source.contains("exploitdb")
                || s.source.contains("exploit")
                || s.sighting_type == "exploited"
        }),
        Err(_) => false,
    }
}

// ── Convenience: get enrichment summary line (for IE integration) ──

pub async fn enrichment_line(cve_id: &str) -> Option<String> {
    let result = lookup_cve(cve_id).await.ok()?;

    let mut parts = vec![format!("VulnLookup: {}", result.title)];

    if let Some(cvss) = result.cvss {
        parts.push(format!("CVSS {:.1}", cvss));
    }
    if let Some(sev) = &result.severity {
        parts.push(sev.clone());
    }

    let exploit_sources: Vec<&str> = result
        .sightings
        .iter()
        .filter(|s| {
            s.sighting_type == "exploited"
                || s.source.contains("exploit")
                || s.source.contains("metasploit")
                || s.source.contains("nuclei")
        })
        .map(|s| s.source.as_str())
        .collect();

    if !exploit_sources.is_empty() {
        parts.push(format!("⚠ Exploit public: {}", exploit_sources.join(", ")));
    }

    if !result.detection_rules.is_empty() {
        parts.push(format!(
            "{} règle(s) détection",
            result.detection_rules.len()
        ));
    }

    Some(parts.join(" | "))
}

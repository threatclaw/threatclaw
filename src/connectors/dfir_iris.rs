//! DFIR-IRIS Connector — import cases and IOCs via REST API.
//!
//! Auth: Bearer API key
//! Cases: GET /manage/cases/list
//! IOCs: GET /case/ioc/list?cid={id}
//! Port: 8443 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfirIrisConfig {
    pub url: String,
    pub api_key: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_cases: u32,
}

fn default_true() -> bool {
    true
}
fn default_limit() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize)]
pub struct DfirIrisSyncResult {
    pub cases_imported: usize,
    pub iocs_imported: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_dfir_iris(store: &dyn Database, config: &DfirIrisConfig) -> DfirIrisSyncResult {
    let mut result = DfirIrisSyncResult {
        cases_imported: 0,
        iocs_imported: 0,
        findings_created: 0,
        errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client: {}", e));
            return result;
        }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("DFIR-IRIS: Connecting to {}", url);

    // Fetch cases
    let resp = match client
        .get(format!("{}/manage/cases/list", url))
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Cases request: {}", e));
            return result;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        result.errors.push(format!(
            "Cases HTTP {}: {}",
            status,
            &text[..text.len().min(200)]
        ));
        return result;
    }

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(e) => {
            result.errors.push(format!("Parse cases: {}", e));
            return result;
        }
    };

    let cases = match data["data"].as_array() {
        Some(c) => c,
        None => {
            tracing::info!("DFIR-IRIS: No cases found");
            return result;
        }
    };

    tracing::info!("DFIR-IRIS: {} cases found", cases.len());

    for case in cases.iter().take(config.max_cases as usize) {
        let case_id = case["case_id"].as_u64().unwrap_or(0);
        let case_name = case["case_name"].as_str().unwrap_or("Unnamed case");
        let case_desc = case["case_description"].as_str().unwrap_or("");
        let soc_id = case["case_soc_id"].as_str().unwrap_or("");
        let state_id = case["state_id"].as_u64().unwrap_or(0);
        let owner = case["owner"].as_str().unwrap_or("");

        // Only import open cases (state_id < 3 typically = open/in_progress)
        if state_id >= 3 {
            continue;
        }

        let _ = store
            .insert_finding(&NewFinding {
                skill_id: "skill-dfir-iris".into(),
                title: format!("[IRIS] {}", case_name),
                description: Some(case_desc.to_string()),
                severity: "HIGH".into(),
                category: Some("incident-response".into()),
                asset: None,
                source: Some("DFIR-IRIS".into()),
                metadata: Some(serde_json::json!({
                    "case_id": case_id,
                    "soc_id": soc_id,
                    "state_id": state_id,
                    "owner": owner,
                })),
            })
            .await;
        result.cases_imported += 1;
        result.findings_created += 1;

        // Fetch IOCs for this case
        match client
            .get(format!("{}/case/ioc/list", url))
            .header("Authorization", format!("Bearer {}", config.api_key))
            .query(&[("cid", case_id.to_string())])
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(ioc_data) = resp.json::<serde_json::Value>().await {
                    if let Some(iocs) = ioc_data["data"].as_array() {
                        for ioc in iocs {
                            let ioc_type = ioc["ioc_type"]
                                .as_str()
                                .or_else(|| ioc["ioc_type_id"].as_str())
                                .unwrap_or("unknown");
                            let ioc_value = ioc["ioc_value"].as_str().unwrap_or("");
                            let ioc_desc = ioc["ioc_description"].as_str().unwrap_or("");

                            if !ioc_value.is_empty() {
                                let _ = store
                                    .insert_finding(&NewFinding {
                                        skill_id: "skill-dfir-iris".into(),
                                        title: format!("[IRIS IOC] {} = {}", ioc_type, ioc_value),
                                        description: Some(format!(
                                            "Case: {} — {}",
                                            case_name, ioc_desc
                                        )),
                                        severity: "MEDIUM".into(),
                                        category: Some("ioc".into()),
                                        asset: None,
                                        source: Some("DFIR-IRIS IOC".into()),
                                        metadata: Some(serde_json::json!({
                                            "case_id": case_id,
                                            "ioc_type": ioc_type,
                                            "ioc_value": ioc_value,
                                            "ioc_tags": ioc["ioc_tags"],
                                            "ioc_tlp": ioc["ioc_tlp"],
                                        })),
                                    })
                                    .await;
                                result.iocs_imported += 1;
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("DFIR-IRIS: IOC fetch for case {}: {}", case_id, e);
            }
        }
    }

    tracing::info!(
        "DFIR-IRIS: Sync done — {} cases, {} IOCs, {} findings",
        result.cases_imported,
        result.iocs_imported,
        result.findings_created
    );
    result
}

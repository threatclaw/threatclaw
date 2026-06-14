//! Sigma rule observability — read-only endpoints feeding the dashboard
//! `/sigma` pages. Mutation endpoints (toggle enable, exceptions, custom
//! rules) live in a separate module that lands with Phase B / D so the
//! read-only surface can ship and stabilise in isolation.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::channels::web::server::GatewayState;

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;

fn db_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn no_db() -> (StatusCode, String) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Database not available".to_string(),
    )
}

/// GET /api/tc/sigma/rules — list all rules joined with the matview.
pub async fn sigma_rules_list_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let rules = store.list_sigma_rules_with_stats().await.map_err(db_err)?;
    Ok(Json(serde_json::json!({ "rules": rules })))
}

/// GET /api/tc/sigma/rules/{id} — single rule with detection_json,
/// 100 most recent alerts and top 5 hostnames over 7 days.
pub async fn sigma_rule_detail_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.get_sigma_rule_detail(&id, 100).await {
        Ok(Some(rule)) => Ok(Json(rule)),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("Rule {} not found", id))),
        Err(e) => Err(db_err(e)),
    }
}

/// GET /api/tc/sigma/coverage/mitre — MITRE ATT&CK coverage map and a
/// ready-to-import Navigator layer JSON (v4.5). The dashboard renders
/// the heatmap inline; an "Open in Navigator" link uses the same payload
/// served at `layer.json`.
pub async fn sigma_coverage_mitre_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let rules = store.list_sigma_rules_with_stats().await.map_err(db_err)?;

    // Aggregate per technique. The score is the count of enabled rules
    // that cover it, clamped to a sensible upper bound for the gradient.
    let mut by_technique: HashMap<String, TechniqueCoverage> = HashMap::new();
    for rule in &rules {
        let enabled = rule.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        if !enabled {
            continue;
        }
        let level = rule.get("level").and_then(|v| v.as_str()).unwrap_or("medium");
        let fire_30d = rule.get("fire_count_30d").and_then(|v| v.as_i64()).unwrap_or(0);

        let empty: Vec<serde_json::Value> = Vec::new();
        let tags = rule
            .get("tags")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);

        for tag in tags {
            let raw = match tag.as_str() {
                Some(s) => s,
                None => continue,
            };
            // Sigma tags are usually `attack.t1110.001` or `attack.execution`.
            // Filter on the technique form: t followed by digits, optional
            // sub-technique.
            let normalised = raw.to_lowercase();
            let stripped = normalised.trim_start_matches("attack.");
            if !stripped.starts_with('t') {
                continue;
            }
            let body = &stripped[1..];
            if !body.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                continue;
            }
            let upper = format!("T{}", body.to_uppercase());

            let entry = by_technique.entry(upper).or_insert_with(TechniqueCoverage::default);
            entry.rule_count += 1;
            entry.fire_count_30d += fire_30d;
            entry.titles.push(
                rule.get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            entry.rule_ids.push(
                rule.get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            // Color gradient driven by sensitivity — high/critical rules
            // weigh more than medium ones.
            let weight = match level {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                _ => 1,
            };
            entry.weight += weight;
        }
    }

    // Sort techniques by id for stable output.
    let mut technique_ids: Vec<String> = by_technique.keys().cloned().collect();
    technique_ids.sort();

    let coverage: Vec<serde_json::Value> = technique_ids
        .iter()
        .map(|tid| {
            let cov = &by_technique[tid];
            serde_json::json!({
                "techniqueID": tid,
                "rule_count": cov.rule_count,
                "fire_count_30d": cov.fire_count_30d,
                "weight": cov.weight,
                "rules": cov.rule_ids,
            })
        })
        .collect();

    // MITRE ATT&CK Navigator layer v4.5 — drop-in for the Navigator UI.
    let max_weight = by_technique
        .values()
        .map(|c| c.weight)
        .max()
        .unwrap_or(1)
        .max(1);
    let layer_techniques: Vec<serde_json::Value> = technique_ids
        .iter()
        .map(|tid| {
            let cov = &by_technique[tid];
            let score = (cov.weight * 100) / max_weight;
            serde_json::json!({
                "techniqueID": tid,
                "score": score,
                "comment": format!(
                    "{} rule(s), {} fires/30d",
                    cov.rule_count, cov.fire_count_30d
                ),
            })
        })
        .collect();

    let layer = serde_json::json!({
        "name": "ThreatClaw detection coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Per-technique coverage derived from enabled detection rules",
        "techniques": layer_techniques,
        "gradient": {
            "colors": ["#ffe1e1", "#d05030", "#7a1010"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "low coverage", "color": "#ffe1e1"},
            {"label": "high coverage", "color": "#7a1010"}
        ]
    });

    Ok(Json(serde_json::json!({
        "coverage": coverage,
        "total_techniques": technique_ids.len(),
        "total_rules_enabled": rules
            .iter()
            .filter(|r| r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
            .count(),
        "layer": layer,
    })))
}

#[derive(Default)]
struct TechniqueCoverage {
    rule_count: i64,
    fire_count_30d: i64,
    weight: i64,
    titles: Vec<String>,
    rule_ids: Vec<String>,
}

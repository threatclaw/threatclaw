//! Forensic enricher — async post-confirmed incident analysis.
//!
//! Runs as a background tokio task. Every 3 minutes it picks the most recent
//! confirmed incident without `forensic_enriched_at` and runs Foundation-Sec
//! Reasoning Q8_0 over it (20-minute timeout, no strict cap).
//!
//! Design choices (see ia-final.md):
//! - One incident at a time: Q8_0 saturates all available RAM while loading.
//! - Scheduler-based (not event-driven): resilient to restarts + retroactively
//!   enriches incidents created before the feature was deployed.
//! - `forensic_enriched_at` stays NULL if the enricher crashes mid-run,
//!   so the next pass retries cleanly.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::agent::llm_router::LlmRouterConfig;
use crate::agent::llm_schemas::forensic_schema;
use crate::agent::react_runner::call_ollama_with_schema;
use crate::db::Database;

const POLL_INTERVAL: Duration = Duration::from_secs(180); // 3 minutes

pub async fn run_forensic_enricher(
    db: Arc<dyn Database>,
    llm_config: LlmRouterConfig,
) {
    info!("Forensic enricher started — polling every {}s", POLL_INTERVAL.as_secs());
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        if let Err(e) = enrich_one(&db, &llm_config).await {
            warn!("Forensic enricher error: {e}");
        }
    }
}

async fn enrich_one(db: &Arc<dyn Database>, llm_config: &LlmRouterConfig) -> Result<(), String> {
    let incidents = db
        .list_confirmed_unenriched_incidents()
        .await
        .map_err(|e| format!("DB query failed: {e}"))?;

    let Some(inc) = incidents.into_iter().next() else {
        debug!("Forensic enricher: no confirmed incidents pending enrichment");
        return Ok(());
    };

    let id = inc["id"].as_i64().unwrap_or(0) as i32;
    let title = inc["title"].as_str().unwrap_or("").to_string();
    let asset = inc["asset"].as_str().unwrap_or("").to_string();
    let severity = inc["severity"].as_str().unwrap_or("MEDIUM").to_string();
    let alert_count = inc["alert_count"].as_i64().unwrap_or(0);
    let existing_summary = inc["summary"].as_str().unwrap_or("").to_string();
    let mitre_existing: Vec<String> = inc["mitre_techniques"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    info!("Forensic enricher: processing incident #{id} — {title}");

    let prompt = build_forensic_prompt(&title, &asset, &severity, alert_count, &existing_summary, &mitre_existing, &inc["proposed_actions"], &inc["evidence_citations"]);

    let result = tokio::time::timeout(
        Duration::from_secs(1200),
        call_ollama_with_schema(
            &llm_config.forensic.base_url,
            &llm_config.forensic.model,
            &prompt,
            Some(forensic_schema()),
        ),
    )
    .await;

    match result {
        Err(_) => {
            warn!("Forensic enricher: timeout on incident #{id} — stamping as enriched without update to avoid retry loop");
            db.mark_forensic_enriched(id, None, None, None)
                .await
                .map_err(|e| format!("DB stamp failed: {e}"))?;
        }
        Ok(Err(e)) => {
            warn!("Forensic enricher: LLM error on incident #{id}: {e}");
            // Do not stamp — will retry next pass (transient error)
        }
        Ok(Ok(raw)) => {
            match parse_forensic_response(&raw) {
                Ok(parsed) => {
                    let mitre: Vec<String> = parsed["mitre_techniques"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let summary = parsed["analysis"].as_str().unwrap_or("").to_string();
                    let evidence_citations = parsed["evidence_citations"].clone();

                    db.mark_forensic_enriched(
                        id,
                        Some(&summary),
                        Some(&mitre),
                        Some(&evidence_citations),
                    )
                    .await
                    .map_err(|e| format!("DB update failed: {e}"))?;

                    info!(
                        "Forensic enricher: incident #{id} enriched — {} MITRE techniques, {}-char narrative",
                        mitre.len(),
                        summary.len()
                    );
                }
                Err(e) => {
                    warn!("Forensic enricher: failed to parse response for incident #{id}: {e}");
                    // Stamp without content — response was malformed, avoid infinite retry
                    db.mark_forensic_enriched(id, None, None, None)
                        .await
                        .map_err(|e2| format!("DB stamp failed: {e2}"))?;
                }
            }
        }
    }

    Ok(())
}

fn build_forensic_prompt(
    title: &str,
    asset: &str,
    severity: &str,
    alert_count: i64,
    existing_summary: &str,
    mitre_existing: &[String],
    proposed_actions: &Value,
    evidence_citations: &Value,
) -> String {
    let mut p = String::with_capacity(4000);

    p.push_str("Tu es un analyste forensique expert. Produis un rapport forensique complet pour le RSSI.\n\n");
    p.push_str("## INCIDENT CONFIRMÉ\n\n");
    p.push_str(&format!("Titre: {title}\n"));
    p.push_str(&format!("Asset: {asset}\n"));
    p.push_str(&format!("Sévérité: {severity}\n"));
    p.push_str(&format!("Nombre d'alertes: {alert_count}\n\n"));

    if !existing_summary.is_empty() {
        p.push_str("### Analyse L1 existante\n\n");
        p.push_str(existing_summary);
        p.push_str("\n\n");
    }

    if !mitre_existing.is_empty() {
        p.push_str("### Techniques MITRE ATT&CK identifiées\n\n");
        for t in mitre_existing {
            p.push_str(&format!("- {t}\n"));
        }
        p.push('\n');
    }

    if let Some(actions) = proposed_actions.as_array() {
        if !actions.is_empty() {
            p.push_str("### Actions proposées\n\n");
            for a in actions {
                if let Some(cmd) = a["cmd_id"].as_str() {
                    let rationale = a["rationale"].as_str().unwrap_or("");
                    p.push_str(&format!("- {cmd}: {rationale}\n"));
                }
            }
            p.push('\n');
        }
    }

    if let Some(cits) = evidence_citations.as_array() {
        if !cits.is_empty() {
            p.push_str("### Preuves disponibles\n\n");
            for c in cits.iter().take(5) {
                let claim = c["claim"].as_str().unwrap_or("");
                let etype = c["evidence_type"].as_str().unwrap_or("");
                p.push_str(&format!("- [{etype}] {claim}\n"));
            }
            p.push('\n');
        }
    }

    p.push_str("### Instructions\n\n");
    p.push_str("1. Rédige une narrative forensique complète (200-400 mots) lisible par un RSSI non-technique.\n");
    p.push_str("2. Confirme ou complète la liste des techniques MITRE ATT&CK.\n");
    p.push_str("3. Identifie les preuves concrètes (alertes, logs, IoC) qui supportent chaque affirmation.\n");
    p.push_str("4. Propose des actions de remédiation précises si pertinent.\n\n");
    p.push_str("Réponds en JSON structuré avec les champs: verdict (confirmed), severity, confidence, analysis (narrative RSSI), mitre_techniques, evidence_citations.\n");

    p
}

fn parse_forensic_response(raw: &str) -> Result<Value, String> {
    let trimmed = raw.trim();
    let json_str = if let Some(start) = trimmed.find('{') {
        &trimmed[start..]
    } else {
        trimmed
    };

    let v: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {e} — raw: {}", &raw[..raw.len().min(200)]))?;

    if v["analysis"].as_str().map(|s| s.len()).unwrap_or(0) < 10 {
        return Err("analysis field too short or missing".to_string());
    }

    Ok(v)
}

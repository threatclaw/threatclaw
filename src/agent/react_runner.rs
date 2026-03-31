//! ReAct Runner — exécute le cycle ReAct sécurisé avec escalade 3 niveaux.
//!
//! Niveau 1 : IA locale rapide → si confiance ≥ 70% → terminé
//! Niveau 2 : IA locale enrichie → si confiance ≥ 50% après retry → terminé
//! Niveau 3 : IA cloud anonymisée → analyse profonde → terminé
//!
//! Le runner connecte tous les piliers au monde réel et orchestre l'escalade.

use std::path::Path;
use std::sync::Arc;

use serde_json::json;

use crate::agent::cloud_caller::{self, AnonymizationMap};
use crate::agent::kill_switch::{KillSwitch, KillSwitchConfig};
use crate::agent::llm_router::{EscalationDecision, LlmRouterConfig};
use crate::agent::memory::{AgentMemory, MemoryEntry};
use crate::agent::mode_manager::{AgentMode, ModeConfig};
use crate::agent::observation_collector::{
    findings_to_observations, alerts_to_observations, ObservationSet,
};
use crate::agent::prompt_builder;
use crate::agent::react_cycle::{self, CycleResult, LlmAnalysis};
use crate::agent::soul::AgentSoul;
use crate::db::threatclaw_store::ThreatClawStore;
use crate::db::Database;

/// Configuration du runner ReAct.
pub struct ReactRunnerConfig {
    pub soul_path: String,
    pub hmac_key: Vec<u8>,
    pub llm: LlmRouterConfig,
    pub max_findings: i64,
    pub max_alerts: i64,
}

impl Default for ReactRunnerConfig {
    fn default() -> Self {
        Self {
            soul_path: concat!(env!("CARGO_MANIFEST_DIR"), "/AGENT_SOUL.toml").to_string(),
            hmac_key: b"threatclaw-default-hmac-key-32b!".to_vec(),
            llm: LlmRouterConfig::default(),
            max_findings: 20,
            max_alerts: 20,
        }
    }
}

/// Résultat d'un cycle ReAct.
pub struct ReactRunResult {
    pub analysis: Option<LlmAnalysis>,
    pub observations_count: usize,
    pub cycle_result: String,
    pub escalation_level: u8,
    pub error: Option<String>,
}

/// Exécute un cycle ReAct complet avec escalade 3 niveaux.
pub async fn run_react_cycle(
    store: Arc<dyn Database>,
    config: &ReactRunnerConfig,
) -> ReactRunResult {
    let soul_path = Path::new(&config.soul_path);

    // ── Étape 0 : Charger le soul ──
    let soul = match AgentSoul::load_and_verify(soul_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("REACT: Soul verification failed: {e}");
            return ReactRunResult {
                analysis: None, observations_count: 0,
                cycle_result: "soul_compromised".to_string(),
                escalation_level: 0, error: Some(e.to_string()),
            };
        }
    };

    // ── Étape 1 : Charger le mode ──
    let mode_str = store.get_setting("_system", "agent_mode").await.ok().flatten()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "investigator".to_string());
    let mode = crate::agent::mode_manager::parse_mode(&mode_str).unwrap_or(AgentMode::Investigator);
    let mode_cfg = ModeConfig::for_mode(mode);

    if !mode_cfg.react_enabled {
        return ReactRunResult {
            analysis: None, observations_count: 0,
            cycle_result: "react_disabled".to_string(),
            escalation_level: 0, error: None,
        };
    }

    // ── Étape 1b : Recharger la config LLM depuis la DB (dashboard) ──
    let llm_config = LlmRouterConfig::from_db_settings(store.as_ref()).await;
    let config = &ReactRunnerConfig {
        soul_path: config.soul_path.clone(),
        hmac_key: config.hmac_key.clone(),
        llm: llm_config,
        max_findings: config.max_findings,
        max_alerts: config.max_alerts,
    };

    // ── Étape 2 : Pre-cycle checks ──
    let memory = match AgentMemory::new(&config.hmac_key) {
        Ok(m) => m,
        Err(e) => return ReactRunResult {
            analysis: None, observations_count: 0,
            cycle_result: "memory_error".to_string(),
            escalation_level: 0, error: Some(e.to_string()),
        },
    };
    let kill_switch = KillSwitch::new(KillSwitchConfig::default());
    let empty_entries: Vec<MemoryEntry> = vec![];

    if let Err(_result) = react_cycle::pre_cycle_checks(&soul, soul_path, &memory, &empty_entries, &kill_switch) {
        return ReactRunResult {
            analysis: None, observations_count: 0,
            cycle_result: "pre_check_failed".to_string(),
            escalation_level: 0, error: Some("Pre-cycle security check failed".to_string()),
        };
    }

    // ── Étape 3 : Collecter les observations ──
    let mut obs = ObservationSet::new();

    if let Ok(findings) = store.list_findings(None, Some("open"), None, config.max_findings, 0).await {
        let values: Vec<serde_json::Value> = findings.iter().map(|f| json!({
            "title": f.title, "severity": f.severity, "asset": f.asset,
            "source": f.source, "skill_id": f.skill_id,
        })).collect();
        for o in findings_to_observations(&values) { obs.add(o); }
    }

    if let Ok(alerts) = store.list_alerts(None, Some("new"), config.max_alerts, 0).await {
        let values: Vec<serde_json::Value> = alerts.iter().map(|a| json!({
            "title": a.title, "level": a.level, "hostname": a.hostname, "rule_id": a.rule_id,
        })).collect();
        for o in alerts_to_observations(&values) { obs.add(o); }
    }

    obs.build_summary();
    let obs_count = obs.len();

    if obs.is_empty() {
        write_audit_entry(&store, &mode, "CYCLE_COMPLETE", None, true, Some("No observations")).await;
        return ReactRunResult {
            analysis: None, observations_count: 0,
            cycle_result: "no_observations".to_string(),
            escalation_level: 0, error: None,
        };
    }

    tracing::info!("REACT: {} observations collected", obs_count);

    // ════════════════════════════════════════════════════════════════
    // NIVEAU 1 — IA principale (locale ou cloud anonymisée)
    // ════════════════════════════════════════════════════════════════
    let lang = prompt_builder::get_language(store.as_ref()).await;
    let prompt_l1_raw = if obs.len() > 10 {
        prompt_builder::build_analyst_prompt(&soul, &obs, &lang)
    } else {
        prompt_builder::build_react_prompt(&soul, &mode_cfg, &obs, &empty_entries, &lang)
    };

    // Si les données quittent l'infra, anonymiser avant envoi
    let anonymize_primary = config.llm.primary_requires_anonymization();
    let mut primary_anon_map = AnonymizationMap::new();
    let prompt_l1 = if anonymize_primary {
        let anonymized = primary_anon_map.anonymize(&prompt_l1_raw);
        tracing::info!("REACT L1: Anonymized {} data points (data leaves infrastructure)", primary_anon_map.mapping_count());
        anonymized
    } else {
        prompt_l1_raw.clone()
    };

    let analysis_l1_raw = match call_primary(&config.llm, &prompt_l1).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("REACT L1: LLM call failed: {e}");
            write_audit_entry(&store, &mode, "LLM_ERROR", None, false, Some(&format!("L1: {e}"))).await;
            return ReactRunResult {
                analysis: None, observations_count: obs_count,
                cycle_result: "llm_error".to_string(),
                escalation_level: 1, error: Some(e),
            };
        }
    };

    // Dé-anonymiser la réponse si on avait anonymisé
    let analysis_l1 = if anonymize_primary {
        deanonymize_analysis(analysis_l1_raw, &primary_anon_map)
    } else {
        analysis_l1_raw
    };

    // ── Log L1 call for future fine-tuning dataset ──
    {
        use crate::db::threatclaw_store::ThreatClawStore;
        use sha2::{Sha256, Digest};
        let prompt_hash = format!("{:x}", Sha256::digest(prompt_l1.as_bytes()));
        let _ = store.log_llm_call(
            &config.llm.primary.model,
            &prompt_hash[..16],
            prompt_l1.len() as i32 / 4, // rough token estimate
            Some(&serde_json::to_value(&analysis_l1).unwrap_or_default()),
            None,
            true, // parsed OK (we got here)
            "strict_or_flexible",
            Some(&analysis_l1.severity),
            Some(analysis_l1.confidence),
            analysis_l1.proposed_actions.len() as i32,
            "pending",
            0, // duration not tracked yet
            obs_count as i32,
        ).await;
    }

    tracing::info!(
        "REACT L1: {} | confiance {:.0}% | {} corrélations",
        analysis_l1.severity, analysis_l1.confidence * 100.0, analysis_l1.correlations.len()
    );

    let decision_l1 = config.llm.decide_escalation(
        analysis_l1.confidence, &analysis_l1.severity, analysis_l1.injection_detected, false,
    );

    if decision_l1 == EscalationDecision::Accept {
        return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
    }

    // ════════════════════════════════════════════════════════════════
    // NIVEAU 2 — IA locale enrichie (plus de contexte)
    // ════════════════════════════════════════════════════════════════
    if decision_l1 == EscalationDecision::RetryLocal {
        let is_critical = analysis_l1.severity == "CRITICAL";
        if is_critical {
            tracing::info!("REACT L2: CRITICAL detected — forensic analysis with L2 model ({})", config.llm.forensic.model);
        } else {
            tracing::info!("REACT L2: Retrying with enriched context");
        }

        // Enrichir le prompt avec l'analyse L1 comme contexte
        // Build graph context for L2 (attackers, CVEs, notes from graph)
        let graph_context = {
            use crate::db::threatclaw_store::ThreatClawStore;
            let recent_alerts = store.list_alerts(None, Some("new"), 3, 0).await.unwrap_or_default();
            let mut ctx_parts = vec![];
            let mut seen_hosts = std::collections::HashSet::new();
            for alert in &recent_alerts {
                if let Some(ref h) = alert.hostname {
                    if seen_hosts.insert(h.clone()) {
                        let ctx = crate::graph::threat_graph::build_investigation_context(store.as_ref(), h).await;
                        if ctx["attackers"].as_array().map(|a| !a.is_empty()).unwrap_or(false)
                            || ctx["cves"].as_array().map(|a| !a.is_empty()).unwrap_or(false)
                            || ctx["analyst_notes"].as_array().map(|a| !a.is_empty()).unwrap_or(false)
                        {
                            ctx_parts.push(format!("Asset {} : {}", h, serde_json::to_string(&ctx).unwrap_or_default()));
                        }
                    }
                }
            }
            if ctx_parts.is_empty() {
                String::new()
            } else {
                format!("\n\n# CONTEXTE GRAPH INTELLIGENCE\n{}", ctx_parts.join("\n"))
            }
        };

        let enriched_prompt_raw = if is_critical {
            // CRITICAL: ask L2 for deep forensic analysis + graph context
            format!(
                "{}\n\n# ANALYSE L1 — INCIDENT CRITIQUE DÉTECTÉ\nSévérité: {} | Confiance: {:.0}%\nAnalyse L1: {}\nCorrélations: {:?}{}\n\n\
                En tant qu'analyste forensique, réalise une analyse approfondie :\n\
                1. Root cause analysis — quel est le vecteur d'attaque initial ?\n\
                2. Kill chain mapping — quelles phases de l'attaque sont confirmées ?\n\
                3. MITRE ATT&CK — quelles techniques sont utilisées ?\n\
                4. Impact — quels systèmes et données sont compromis ?\n\
                5. Mouvement latéral — l'attaquant a-t-il pivoté vers d'autres assets ?\n\
                6. Actions immédiates — que doit faire le RSSI maintenant ?\n\
                Utilise le contexte graph pour enrichir ton analyse.",
                prompt_l1_raw, analysis_l1.severity, analysis_l1.confidence * 100.0,
                analysis_l1.analysis, analysis_l1.correlations, graph_context
            )
        } else {
            format!(
                "{}\n\n# ANALYSE PRÉCÉDENTE (confiance insuffisante — réanalyse demandée)\n{}\nCorrélations identifiées: {:?}\n\nRéanalyse avec plus d'attention aux détails. Augmente ta confiance si l'analyse est correcte.",
                prompt_l1_raw, analysis_l1.analysis, analysis_l1.correlations
            )
        };

        // Anonymiser L2 si données quittent l'infra
        let enriched_prompt = if anonymize_primary {
            let mut l2_anon = AnonymizationMap::new();
            let anon = l2_anon.anonymize(&enriched_prompt_raw);
            tracing::info!("REACT L2: Anonymized {} data points", l2_anon.mapping_count());
            anon
        } else {
            enriched_prompt_raw
        };

        // Use L2 forensic model for CRITICAL, L1 for retries
        let analysis_l2_raw = if is_critical {
            match call_ollama(&config.llm.forensic.base_url, &config.llm.forensic.model, &enriched_prompt).await {
                Ok(response) => match react_cycle::parse_llm_response(&response) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!("REACT L2: Forensic JSON parse failed: {e} — falling back to L1");
                        return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
                    }
                },
                Err(e) => {
                    tracing::warn!("REACT L2: Forensic model failed: {e} — falling back to L1");
                    return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
                }
            }
        } else {
            match call_primary(&config.llm, &enriched_prompt).await {
                Ok(a) => a,
                Err(_) => {
                    return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
                }
            }
        };

        let analysis_l2 = if anonymize_primary {
            deanonymize_analysis(analysis_l2_raw, &primary_anon_map)
        } else {
            analysis_l2_raw
        };

        tracing::info!(
            "REACT L2: {} | confiance {:.0}% | {} corrélations",
            analysis_l2.severity, analysis_l2.confidence * 100.0, analysis_l2.correlations.len()
        );

        let decision_l2 = config.llm.decide_escalation(
            analysis_l2.confidence, &analysis_l2.severity, analysis_l2.injection_detected, true,
        );

        if decision_l2 == EscalationDecision::Accept || decision_l2 == EscalationDecision::AcceptDegraded {
            return finalize_cycle(store, &mode, analysis_l2, obs_count, 2).await;
        }

        // L2 not sufficient, try cloud if available
        if decision_l2 != EscalationDecision::EscalateCloud {
            return finalize_cycle(store, &mode, analysis_l2, obs_count, 2).await;
        }
    }

    // ════════════════════════════════════════════════════════════════
    // NIVEAU 3 — IA cloud anonymisée
    // ════════════════════════════════════════════════════════════════
    let cloud_config = match &config.llm.cloud {
        Some(c) => c,
        None => {
            tracing::info!("REACT: Cloud not configured, accepting local analysis (degraded)");
            return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
        }
    };

    tracing::info!("REACT L3: Escalating to cloud ({}/{})", cloud_config.backend, cloud_config.model);

    // Anonymiser le prompt (utiliser prompt_l1_raw pour éviter la double-anonymisation)
    let mut anon_map = AnonymizationMap::new();
    let cloud_prompt = if config.llm.requires_anonymization() {
        let anonymized = anon_map.anonymize(&prompt_l1_raw);
        tracing::info!("REACT L3: Anonymized {} data points", anon_map.mapping_count());
        anonymized
    } else {
        prompt_l1_raw.clone()
    };

    let cloud_result = match cloud_caller::call_cloud_llm(cloud_config, &cloud_prompt).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("REACT L3: Cloud call failed: {e}");
            write_audit_entry(&store, &mode, "CLOUD_ERROR", None, false, Some(&format!("L3: {e}"))).await;
            // Fallback to L1 analysis
            return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
        }
    };

    // Dé-anonymiser la réponse
    let cloud_response = if config.llm.requires_anonymization() {
        anon_map.deanonymize(&cloud_result.response)
    } else {
        cloud_result.response
    };

    // Parser la réponse cloud
    let analysis_l3 = match react_cycle::parse_llm_response(&cloud_response) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("REACT L3: Failed to parse cloud JSON: {e}");
            // Fallback to L1
            return finalize_cycle(store, &mode, analysis_l1, obs_count, 1).await;
        }
    };

    tracing::info!(
        "REACT L3: {} | confiance {:.0}% | {} corrélations (cloud: {}/{})",
        analysis_l3.severity, analysis_l3.confidence * 100.0,
        analysis_l3.correlations.len(), cloud_config.backend, cloud_config.model,
    );

    if let Some(tokens) = cloud_result.tokens_used {
        tracing::info!("REACT L3: {} tokens cloud utilisés", tokens);
    }

    write_audit_entry(&store, &mode, "CLOUD_ESCALATION", None, true,
        Some(&format!("L3 cloud ({}/{}) — confiance {:.0}%", cloud_config.backend, cloud_config.model, analysis_l3.confidence * 100.0))).await;

    finalize_cycle(store, &mode, analysis_l3, obs_count, 3).await
}

/// Finalise le cycle : valide les actions, écrit l'audit, enregistre les métriques.
async fn finalize_cycle(
    store: Arc<dyn Database>,
    mode: &AgentMode,
    analysis: LlmAnalysis,
    obs_count: usize,
    level: u8,
) -> ReactRunResult {
    if analysis.injection_detected {
        tracing::error!("REACT: Injection detected in observations!");
        write_audit_entry(&store, mode, "INJECTION_DETECTED", None, true, Some(&analysis.analysis)).await;
        return ReactRunResult {
            analysis: Some(analysis), observations_count: obs_count,
            cycle_result: "injection_detected".to_string(),
            escalation_level: level, error: None,
        };
    }

    let ks = Arc::new(KillSwitch::new(KillSwitchConfig::default()));
    let (validated, errors) = react_cycle::validate_proposed_actions(&analysis.proposed_actions, &ks);
    if !errors.is_empty() {
        tracing::warn!("REACT: {} action(s) rejected: {:?}", errors.len(), errors);
    }

    let summary = format!(
        "L{} | {} | Confiance: {:.0}% | Corrélations: {} | Actions: {} ({} validées)",
        level, analysis.severity, analysis.confidence * 100.0,
        analysis.correlations.len(), analysis.proposed_actions.len(), validated.len(),
    );

    write_audit_entry(&store, mode, "CYCLE_COMPLETE", None, true, Some(&summary)).await;
    let _ = store.record_metric("security_score", analysis.confidence * 100.0, &json!({})).await;

    tracing::info!("REACT: {}", summary);

    ReactRunResult {
        analysis: Some(analysis), observations_count: obs_count,
        cycle_result: "success".to_string(),
        escalation_level: level, error: None,
    }
}

/// Appelle l'IA principale (Ollama ou API cloud) et parse la réponse JSON.
async fn call_primary(llm: &LlmRouterConfig, prompt: &str) -> Result<LlmAnalysis, String> {
    if llm.primary_uses_cloud_api() {
        // Primary is cloud — use cloud_caller via a CloudLlmConfig adapter
        let cloud_cfg = crate::agent::llm_router::CloudLlmConfig {
            backend: llm.primary.backend.clone(),
            model: llm.primary.model.clone(),
            base_url: Some(llm.primary.base_url.clone()),
            api_key: llm.primary.api_key.clone().unwrap_or_default(),
        };
        let result = cloud_caller::call_cloud_llm(&cloud_cfg, prompt).await?;
        react_cycle::parse_llm_response(&result.response)
            .map_err(|e| format!("JSON parse failed: {e}"))
    } else {
        // Local Ollama
        let response = call_ollama(&llm.primary.base_url, &llm.primary.model, prompt).await?;
        react_cycle::parse_llm_response(&response)
            .map_err(|e| format!("JSON parse failed: {e}"))
    }
}

/// Dé-anonymise les champs texte d'une analyse LLM.
fn deanonymize_analysis(mut analysis: LlmAnalysis, anon_map: &AnonymizationMap) -> LlmAnalysis {
    analysis.analysis = anon_map.deanonymize(&analysis.analysis);
    analysis.correlations = analysis.correlations.iter()
        .map(|c| anon_map.deanonymize(c))
        .collect();
    analysis.proposed_actions = analysis.proposed_actions.iter()
        .map(|a| {
            let mut action = a.clone();
            action.rationale = anon_map.deanonymize(&action.rationale);
            action.cmd_id = anon_map.deanonymize(&action.cmd_id);
            action.params = action.params.iter()
                .map(|(k, v)| (k.clone(), anon_map.deanonymize(v)))
                .collect();
            action
        })
        .collect();
    analysis
}

/// Appelle Ollama et parse la réponse JSON.
async fn call_and_parse(base_url: &str, model: &str, prompt: &str) -> Result<LlmAnalysis, String> {
    let response = call_ollama(base_url, model, prompt).await?;
    react_cycle::parse_llm_response(&response)
        .map_err(|e| format!("JSON parse failed: {e}"))
}

/// Appelle Ollama via l'API Chat (plus fiable que generate pour le JSON structuré).
pub(crate) async fn call_ollama(base_url: &str, model: &str, prompt: &str) -> Result<String, String> {
    let url = format!("{}/api/chat", base_url);
    let body = json!({
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": format!("{prompt}\n\nRéponds UNIQUEMENT en JSON valide. Pas de texte avant ou après le JSON. Pas de markdown. /no_think")
            }
        ],
        "stream": false,
        "options": { "temperature": 0.1, "num_predict": 2048 }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client.post(&url).json(&body).send().await
        .map_err(|e| format!("Ollama request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Ollama returned {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON parse error: {e}"))?;

    // Chat API: response is in message.content
    if let Some(content) = data["message"]["content"].as_str() {
        if !content.is_empty() {
            return Ok(content.to_string());
        }
    }

    // Fallback: try generate API format (response field)
    if let Some(response) = data["response"].as_str() {
        if !response.is_empty() {
            return Ok(response.to_string());
        }
    }

    // Fallback: some models put content in thinking field
    if let Some(thinking) = data["message"]["thinking"].as_str() {
        if !thinking.is_empty() {
            tracing::warn!("LLM responded in thinking field instead of content — using thinking as response");
            return Ok(thinking.to_string());
        }
    }

    Err(format!("No usable response from Ollama. Raw: {}", serde_json::to_string(&data).unwrap_or_default()))
}

/// Écrit une entrée dans l'audit log.
async fn write_audit_entry(
    store: &Arc<dyn Database>,
    mode: &AgentMode,
    event_type: &str,
    cmd_id: Option<&str>,
    success: bool,
    summary: Option<&str>,
) {
    let audit_key = format!("audit_{}_{}", event_type, chrono::Utc::now().timestamp());
    let audit_value = json!({
        "event_type": event_type, "agent_mode": mode.to_string(),
        "cmd_id": cmd_id, "success": success, "summary": summary,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    if let Err(e) = store.set_setting("_audit", &audit_key, &audit_value).await {
        tracing::error!("Failed to write audit entry: {e}");
    }
}

/// Lance le ticker cron pour le cycle ReAct.
pub fn spawn_react_ticker(
    store: Arc<dyn Database>,
    config: ReactRunnerConfig,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("REACT: Ticker started — cycle every {}s", interval.as_secs());
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first

        loop {
            ticker.tick().await;
            tracing::info!("REACT: Starting cycle...");
            let result = run_react_cycle(store.clone(), &config).await;
            match result.cycle_result.as_str() {
                "success" => {
                    if let Some(ref a) = result.analysis {
                        tracing::info!("REACT: L{} — {} | {:.0}% | {} actions",
                            result.escalation_level, a.severity, a.confidence * 100.0, a.proposed_actions.len());
                    }
                }
                "no_observations" => tracing::debug!("REACT: No observations"),
                other => tracing::warn!("REACT: {other} — {:?}", result.error),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ReactRunnerConfig::default();
        assert!(config.soul_path.contains("AGENT_SOUL.toml"));
        let expected_model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "threatclaw-redsage".to_string());
        assert_eq!(config.llm.primary.model, expected_model);
        assert!(config.llm.cloud.is_none());
    }

    #[tokio::test]
    async fn test_call_ollama_invalid_url() {
        let result = call_ollama("http://127.0.0.1:99999", "test", "hello").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_react_run_result_structure() {
        let result = ReactRunResult {
            analysis: None, observations_count: 5,
            cycle_result: "success".to_string(),
            escalation_level: 2, error: None,
        };
        assert_eq!(result.escalation_level, 2);
        assert_eq!(result.observations_count, 5);
    }
}

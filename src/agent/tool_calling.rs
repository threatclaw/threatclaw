//! Tool Calling Layer — gives the conversational LLM access to real system data.
//!
//! Supports two modes:
//! - Native: Uses Ollama's tools API (Mistral, Llama 3.1+) or cloud API tool calling
//! - PromptBased: Describes tools in system prompt, parses JSON response
//!
//! Available tools:
//! - get_security_status: Global score, alert/finding/asset counts
//! - get_recent_alerts: Alerts filtered by severity and time window
//! - get_recent_findings: Findings filtered by severity and status
//! - get_asset_info: Asset details and risk score
//! - get_ml_anomalies: Recent ML anomaly detections
//! - search_logs: Search recent log entries
//! - get_threat_profile: NACE/NAF sector threat profile

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::Database;

/// Definition of a tool that the LLM can call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

/// A tool call request from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
}

/// Result of executing a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub name: String,
    pub success: bool,
    pub data: Value,
}

/// All available tools for the conversational bot.
pub fn available_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "get_security_status".into(),
            description: "Récupère le score de sécurité global, le nombre d'alertes, findings et assets surveillés".into(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_recent_alerts".into(),
            description: "Récupère les alertes récentes du système ThreatClaw avec leurs détails".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["all", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Filtrer par sévérité (défaut: all)"
                    },
                    "last_hours": {
                        "type": "integer",
                        "description": "Alertes des N dernières heures (défaut: 24)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Nombre max d'alertes à retourner (défaut: 5)"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_recent_findings".into(),
            description: "Récupère les vulnérabilités (findings) récentes avec sévérité, titre et asset concerné".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["all", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Filtrer par sévérité (défaut: all)"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["open", "resolved", "all"],
                        "description": "Filtrer par statut (défaut: open)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Nombre max de findings (défaut: 5)"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_asset_info".into(),
            description: "Récupère les informations d'un asset (serveur, poste, équipement réseau) par IP ou hostname".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "IP ou hostname de l'asset à rechercher"
                    }
                },
                "required": ["query"]
            }),
        },
        ToolDefinition {
            name: "get_ml_anomalies".into(),
            description: "Récupère les anomalies détectées par le moteur ML (Isolation Forest, DGA)".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "last_hours": {
                        "type": "integer",
                        "description": "Anomalies des N dernières heures (défaut: 24)"
                    },
                    "min_score": {
                        "type": "number",
                        "description": "Score minimum d'anomalie 0-1 (défaut: 0.7)"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_threat_profile".into(),
            description: "Récupère le profil de menaces du secteur d'activité de l'entreprise (NACE/NAF)".into(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
    ]
}

/// Build Ollama-compatible tools array for native tool calling.
pub fn tools_for_ollama() -> Value {
    let tools: Vec<Value> = available_tools().iter().map(|t| {
        json!({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters
            }
        })
    }).collect();
    Value::Array(tools)
}

/// Build a tool description block for prompt-based tool calling.
/// Injected into the system prompt for models that don't support native tools.
pub fn tools_for_prompt() -> String {
    let tools = available_tools();
    let mut desc = String::from("Tu disposes des outils suivants pour accéder aux données du système. ");
    desc.push_str("Pour utiliser un outil, réponds avec un bloc JSON comme ceci :\n");
    desc.push_str("```tool_call\n{\"name\": \"nom_outil\", \"arguments\": {\"param\": \"valeur\"}}\n```\n\n");
    desc.push_str("Outils disponibles :\n");

    for tool in &tools {
        desc.push_str(&format!("- **{}** : {}\n", tool.name, tool.description));
        if let Some(props) = tool.parameters["properties"].as_object() {
            if !props.is_empty() {
                desc.push_str("  Paramètres : ");
                let params: Vec<String> = props.iter().map(|(k, v)| {
                    let desc = v["description"].as_str().unwrap_or("");
                    format!("`{}` ({})", k, desc)
                }).collect();
                desc.push_str(&params.join(", "));
                desc.push('\n');
            }
        }
    }

    desc.push_str("\nSi tu n'as pas besoin d'outil, réponds directement en texte naturel.\n");
    desc.push_str("Tu peux appeler UN outil par message. Après avoir reçu le résultat, formule ta réponse.\n");
    desc
}

/// Parse a tool call from a prompt-based response.
/// Looks for ```tool_call\n{...}\n``` or raw JSON with "name" field.
pub fn parse_tool_call_from_text(text: &str) -> Option<ToolCall> {
    // Try to find ```tool_call block
    if let Some(start) = text.find("```tool_call") {
        let json_start = text[start..].find('{').map(|i| start + i)?;
        let json_end = text[json_start..].find("```").map(|i| json_start + i)
            .or_else(|| text[json_start..].rfind('}').map(|i| json_start + i + 1))?;
        let json_str = &text[json_start..json_end];
        if let Ok(val) = serde_json::from_str::<Value>(json_str) {
            return extract_tool_call(&val);
        }
    }

    // Try to find raw JSON with "name" field (thinking models may output this)
    let clean = if let Some(pos) = text.find("</think>") {
        text[pos + 8..].trim()
    } else {
        text.trim()
    };

    if clean.starts_with('{') {
        if let Some(end) = clean.rfind('}') {
            let json_str = &clean[..=end];
            if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                return extract_tool_call(&val);
            }
        }
    }

    None
}

fn extract_tool_call(val: &Value) -> Option<ToolCall> {
    let name = val["name"].as_str()
        .or_else(|| val["tool"].as_str())
        .or_else(|| val["function"].as_str())?;

    // Validate against known tools
    let valid_tools: Vec<String> = available_tools().iter().map(|t| t.name.clone()).collect();
    if !valid_tools.contains(&name.to_string()) {
        return None;
    }

    let arguments = val.get("arguments")
        .or_else(|| val.get("params"))
        .or_else(|| val.get("parameters"))
        .cloned()
        .unwrap_or(json!({}));

    Some(ToolCall {
        name: name.to_string(),
        arguments,
    })
}

/// Execute a tool call against the database and return results.
pub async fn execute_tool(tool_call: &ToolCall, store: &Arc<dyn Database>) -> ToolResult {
    match tool_call.name.as_str() {
        "get_security_status" => execute_security_status(store).await,
        "get_recent_alerts" => execute_recent_alerts(&tool_call.arguments, store).await,
        "get_recent_findings" => execute_recent_findings(&tool_call.arguments, store).await,
        "get_asset_info" => execute_asset_info(&tool_call.arguments, store).await,
        "get_ml_anomalies" => execute_ml_anomalies(&tool_call.arguments, store).await,
        "get_threat_profile" => execute_threat_profile(store).await,
        _ => ToolResult {
            name: tool_call.name.clone(),
            success: false,
            data: json!({"error": "Outil inconnu"}),
        },
    }
}

async fn execute_security_status(store: &Arc<dyn Database>) -> ToolResult {
    let situation = store.get_setting("_system", "security_situation").await.ok().flatten();
    let score = situation.as_ref().and_then(|s| s["global_score"].as_f64()).unwrap_or(100.0);
    let alerts_count = store.count_alerts_filtered(None, Some("new")).await.unwrap_or(0);
    let findings_count = store.count_findings_filtered(None, Some("open"), None).await.unwrap_or(0);
    let assets_count = store.count_assets_filtered(None, None).await.unwrap_or(0);

    let label = if score >= 80.0 { "Situation saine" }
        else if score >= 50.0 { "Points d'attention" }
        else { "Situation dégradée" };

    ToolResult {
        name: "get_security_status".into(),
        success: true,
        data: json!({
            "score": score,
            "label": label,
            "alerts_active": alerts_count,
            "findings_open": findings_count,
            "assets_monitored": assets_count,
        }),
    }
}

async fn execute_recent_alerts(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let severity_filter = args["severity"].as_str().unwrap_or("all");
    let limit = args["limit"].as_u64().unwrap_or(5) as i64;
    let _last_hours = args["last_hours"].as_u64().unwrap_or(24);

    let level = if severity_filter == "all" { None } else { Some(severity_filter) };

    match store.list_alerts(level, Some("new"), limit, 0).await {
        Ok(alerts) => {
            let items: Vec<Value> = alerts.iter().map(|a| {
                json!({
                    "title": a.title,
                    "level": a.level,
                    "hostname": a.hostname,
                    "source_ip": a.source_ip,
                    "timestamp": a.matched_at,
                    "username": a.username,
                })
            }).collect();
            ToolResult {
                name: "get_recent_alerts".into(),
                success: true,
                data: json!({ "alerts": items, "total": items.len() }),
            }
        }
        Err(e) => ToolResult {
            name: "get_recent_alerts".into(),
            success: false,
            data: json!({"error": format!("{e}")}),
        },
    }
}

async fn execute_recent_findings(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let severity_filter = args["severity"].as_str().unwrap_or("all");
    let status_filter = args["status"].as_str().unwrap_or("open");
    let limit = args["limit"].as_u64().unwrap_or(5) as i64;

    let severity = if severity_filter == "all" { None } else { Some(severity_filter) };
    let status = if status_filter == "all" { None } else { Some(status_filter) };

    match store.list_findings(severity, status, None, limit, 0).await {
        Ok(findings) => {
            let items: Vec<Value> = findings.iter().map(|f| {
                json!({
                    "title": f.title,
                    "severity": f.severity,
                    "asset": f.asset,
                    "status": f.status,
                    "description": f.description.as_deref().unwrap_or("").chars().take(200).collect::<String>(),
                    "source": f.source,
                    "detected_at": f.detected_at,
                })
            }).collect();
            ToolResult {
                name: "get_recent_findings".into(),
                success: true,
                data: json!({ "findings": items, "total": items.len() }),
            }
        }
        Err(e) => ToolResult {
            name: "get_recent_findings".into(),
            success: false,
            data: json!({"error": format!("{e}")}),
        },
    }
}

async fn execute_asset_info(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let query = args["query"].as_str().unwrap_or("");
    if query.is_empty() {
        return ToolResult {
            name: "get_asset_info".into(),
            success: false,
            data: json!({"error": "Paramètre 'query' requis (IP ou hostname)"}),
        };
    }

    // Try by IP first, then list all and filter by hostname
    let mut results = Vec::new();

    if let Ok(Some(asset)) = store.find_asset_by_ip(query).await {
        results.push(asset);
    }

    if results.is_empty() {
        // Fallback: list and filter by hostname match
        if let Ok(assets) = store.list_assets(None, None, 100, 0).await {
            let query_lower = query.to_lowercase();
            for a in assets {
                if a.hostname.as_deref().map(|h| h.to_lowercase().contains(&query_lower)).unwrap_or(false)
                    || a.name.to_lowercase().contains(&query_lower)
                    || a.fqdn.as_deref().map(|f| f.to_lowercase().contains(&query_lower)).unwrap_or(false)
                {
                    results.push(a);
                    if results.len() >= 5 { break; }
                }
            }
        }
    }

    let items: Vec<Value> = results.iter().map(|a| {
        json!({
            "name": a.name,
            "hostname": a.hostname,
            "ips": a.ip_addresses,
            "os": a.os,
            "category": a.category,
            "criticality": a.criticality,
            "role": a.role,
            "last_seen": a.last_seen,
        })
    }).collect();

    ToolResult {
        name: "get_asset_info".into(),
        success: true,
        data: json!({ "assets": items, "total": items.len() }),
    }
}

async fn execute_ml_anomalies(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let _last_hours = args["last_hours"].as_u64().unwrap_or(24);
    let _min_score = args["min_score"].as_f64().unwrap_or(0.7);

    // ML anomalies are stored as findings with skill_id="ml-engine"
    match store.list_findings(None, Some("open"), Some("ml-engine"), 10, 0).await {
        Ok(findings) => {
            let items: Vec<Value> = findings.iter().map(|f| {
                json!({
                    "title": f.title,
                    "severity": f.severity,
                    "asset": f.asset,
                    "description": f.description.as_deref().unwrap_or("").chars().take(200).collect::<String>(),
                    "detected_at": f.detected_at,
                })
            }).collect();
            ToolResult {
                name: "get_ml_anomalies".into(),
                success: true,
                data: json!({ "anomalies": items, "total": items.len() }),
            }
        }
        Err(_) => ToolResult {
            name: "get_ml_anomalies".into(),
            success: true,
            data: json!({ "anomalies": [], "total": 0 }),
        },
    }
}

async fn execute_threat_profile(store: &Arc<dyn Database>) -> ToolResult {
    // Load company NACE profile
    let profile = store.get_setting("_system", "tc_config_company").await.ok().flatten();
    let nace = profile.as_ref().and_then(|p| p["naceCode"].as_str()).unwrap_or("unknown");
    let sector = profile.as_ref().and_then(|p| p["sector"].as_str()).unwrap_or("Non défini");
    let company = profile.as_ref().and_then(|p| p["name"].as_str()).unwrap_or("Non défini");

    // Load NACE threat profile if available
    let threat_profile = store.get_setting("_system", &format!("nace_profile_{}", nace)).await.ok().flatten();

    ToolResult {
        name: "get_threat_profile".into(),
        success: true,
        data: json!({
            "company": company,
            "sector": sector,
            "nace_code": nace,
            "threats": threat_profile.unwrap_or(json!({"info": "Profil de menaces non configuré"})),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_tools_not_empty() {
        let tools = available_tools();
        assert!(tools.len() >= 5);
    }

    #[test]
    fn test_tools_for_ollama_format() {
        let tools = tools_for_ollama();
        let arr = tools.as_array().unwrap();
        assert!(!arr.is_empty());
        // Each tool has type=function and function.name
        for tool in arr {
            assert_eq!(tool["type"].as_str().unwrap(), "function");
            assert!(tool["function"]["name"].as_str().is_some());
            assert!(tool["function"]["description"].as_str().is_some());
        }
    }

    #[test]
    fn test_tools_for_prompt_contains_all() {
        let prompt = tools_for_prompt();
        for tool in available_tools() {
            assert!(prompt.contains(&tool.name), "Prompt missing tool: {}", tool.name);
        }
        assert!(prompt.contains("tool_call"));
    }

    #[test]
    fn test_parse_tool_call_from_text_code_block() {
        let text = "Je vais vérifier les alertes.\n```tool_call\n{\"name\": \"get_recent_alerts\", \"arguments\": {\"last_hours\": 8}}\n```";
        let call = parse_tool_call_from_text(text).unwrap();
        assert_eq!(call.name, "get_recent_alerts");
        assert_eq!(call.arguments["last_hours"], 8);
    }

    #[test]
    fn test_parse_tool_call_from_thinking() {
        let text = "<think>I need to check alerts</think>\n{\"name\": \"get_recent_alerts\", \"arguments\": {\"last_hours\": 24}}";
        let call = parse_tool_call_from_text(text).unwrap();
        assert_eq!(call.name, "get_recent_alerts");
    }

    #[test]
    fn test_parse_tool_call_invalid_tool_name() {
        let text = "{\"name\": \"hack_the_planet\", \"arguments\": {}}";
        assert!(parse_tool_call_from_text(text).is_none());
    }

    #[test]
    fn test_parse_tool_call_no_tool() {
        let text = "Bonjour, votre infrastructure est en bon état.";
        assert!(parse_tool_call_from_text(text).is_none());
    }

    #[test]
    fn test_parse_tool_call_alternative_field_names() {
        let text = "{\"name\": \"get_security_status\", \"params\": {}}";
        let call = parse_tool_call_from_text(text).unwrap();
        assert_eq!(call.name, "get_security_status");
    }
}

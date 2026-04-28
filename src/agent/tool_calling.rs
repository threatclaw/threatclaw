//! Tool Calling Layer. See ADR-032.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::db::Database;
use crate::licensing::LicenseManager;

/// Maps a tool name to the premium skill it requires, or `None` for free
/// tools. Tools listed here will refuse to execute unless the runtime
/// license gate covers their skill.
///
/// Adding a new premium tool: register the tool's `name` here, then make
/// sure callers wrap their `execute_tool` call with [`check_tool_license`]
/// so the gate fires before the underlying VQL / API call is issued.
///
/// **Why a static map vs a manifest field**: tool definitions live in
/// Rust code (see [`available_tools`]); the gate decision is also a
/// Rust concern. Keeping the mapping next to the tool registration
/// minimises drift between "I added a premium tool" and "I forgot to
/// gate it".
/// Returns true when a short "dashboard action" verb (the strings the
/// /incidents page POSTs as `{"action": "block_ip"}`) is a destructive
/// HITL action. Used by the http handler to gate the Approve button.
/// Mirrors [`tool_requires_hitl`] for the LLM tool path.
pub fn dashboard_action_requires_hitl(action: &str) -> bool {
    matches!(
        action,
        // Firewall remediation
        "block_ip"
        | "approve_remediate"  // legacy alias for block_ip
        | "kill_states"
        | "quarantine_mac"
        // Identity remediation
        | "disable_account"
        | "reset_password"
        // EDR remediation
        | "quarantine_endpoint"
        | "isolate_host"
        | "kill_process"
    )
}

/// Returns true when the tool is a destructive HITL action (quarantine,
/// block IP, disable account, etc.). Free tools — read-only DB queries,
/// VQL lookups, asset enrichments — return false and run without any
/// license check.
///
/// Doctrine pivot 2026-04-26: the licensing model moved from
/// "per-skill premium" (skill-velociraptor-actions, skill-opnsense-actions,
/// ...) to a single "ThreatClaw Action Pack" that unlocks every HITL
/// destructive flow at once. See SCAN_REFACTOR_PLAN.md / hitl_actions in
/// the skill manifests.
pub fn tool_requires_hitl(tool_name: &str) -> bool {
    matches!(
        tool_name,
        // EDR endpoint remediation
        "velociraptor_quarantine_endpoint"
        | "velociraptor_kill_process"
        | "velociraptor_isolate_host"
        // Firewall HITL actions
        | "opnsense_block_ip"
        | "opnsense_kill_states"
        | "opnsense_quarantine_mac"
        | "pfsense_block_ip"
        | "fortinet_block_ip"
        | "fortinet_block_url"
        // Identity remediation
        | "ad_disable_account"
        | "ad_reset_password"
    )
}

/// Verify that a tool is allowed to execute under the current license.
///
/// - **Free tools** (where [`tool_requires_hitl`] returns false) always pass.
/// - **HITL tools** require an active "Action Pack" license. Without one,
///   returns an explanatory error the caller should surface verbatim.
///
/// Call **before** `execute_tool` at any site that may dispatch HITL
/// actions (approval flow, dashboard buttons, L2 forensic agent).
pub async fn check_tool_license(
    tool_name: &str,
    license_manager: Option<&Arc<LicenseManager>>,
) -> Result<(), String> {
    // Phase A.1 (2026-04-28 pricing pivot) — HITL is now free for every
    // tier including the unlicensed Free instance. The asset-count
    // tier is the only paid lever; gating an emergency response button
    // behind a paywall created moral friction at the worst moment.
    //
    // The function is kept (rather than deleted) so call-sites at the
    // approval flow, the dashboard, and the L2 forensic agent compile
    // without changes — and so a future surgical re-gating of one
    // specific destructive action is possible without rewiring the
    // pipeline.
    let _ = (tool_name, license_manager);
    Ok(())
}

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
        // ── Velociraptor: active endpoint investigation ──
        // Four read-only tools for the L2 forensic LLM. The Velociraptor
        // API user is provisioned with the `investigator` role which
        // already blocks write/exec plugins server-side — these tools
        // rely on that ACL as their primary safety gate, plus a
        // client-side VQL lint for defence-in-depth.
        ToolDefinition {
            name: "velociraptor_list_clients".into(),
            description: "Liste les endpoints (clients) connus du serveur Velociraptor avec hostname, OS, dernière connexion. Utile avant d'investiguer — commencer par savoir quels assets sont couverts.".into(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "velociraptor_query".into(),
            description: "Exécute une requête VQL lecture-seule sur le serveur Velociraptor (pas sur un endpoint spécifique). Pour des questions globales : lister les hunts récents, compter les clients par OS, chercher un flow qui a échoué. Refuse les plugins write/exec côté serveur et client.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "vql": {
                        "type": "string",
                        "description": "La requête VQL. Ex: 'SELECT client_id, os_info.hostname FROM clients() LIMIT 20'"
                    }
                },
                "required": ["vql"]
            }),
        },
        ToolDefinition {
            name: "velociraptor_hunt".into(),
            description: "Lance un hunt (collecte d'artifact) fleet-wide. Utiliser pour chercher un IOC ou un pattern sur tout le parc. Retourne un hunt_id que l'opérateur peut suivre dans l'UI Velociraptor.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Description courte du hunt (apparaît dans l'UI Velociraptor + ThreatClaw findings)"
                    },
                    "artifacts": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Noms d'artifacts à collecter. Ex: ['Windows.Detection.PsExec', 'Generic.Client.Info']"
                    }
                },
                "required": ["description", "artifacts"]
            }),
        },
        ToolDefinition {
            name: "velociraptor_collect".into(),
            description: "Collecte un artifact sur UN endpoint spécifique. Utiliser pendant une investigation incident pour aller chercher l'évidence sur la machine suspecte. Ex: grab Amcache sur C.xxx pour confirmer l'exécution d'un binaire.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "ID Velociraptor du client (format 'C.' + 16 hex). Utiliser velociraptor_list_clients pour le trouver."
                    },
                    "artifact": {
                        "type": "string",
                        "description": "Nom de l'artifact. Ex: 'Windows.System.Amcache', 'Generic.Client.Info', 'Linux.Sys.SSHAuthKeys'"
                    }
                },
                "required": ["client_id", "artifact"]
            }),
        },
    ]
}

/// Build Ollama-compatible tools array for native tool calling.
pub fn tools_for_ollama() -> Value {
    let tools: Vec<Value> = available_tools()
        .iter()
        .map(|t| {
            json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters
                }
            })
        })
        .collect();
    Value::Array(tools)
}

/// Build a tool description block for prompt-based tool calling.
/// Injected into the system prompt for models that don't support native tools.
pub fn tools_for_prompt() -> String {
    let tools = available_tools();
    let mut desc =
        String::from("Tu disposes des outils suivants pour accéder aux données du système. ");
    desc.push_str("Pour utiliser un outil, réponds avec un bloc JSON comme ceci :\n");
    desc.push_str(
        "```tool_call\n{\"name\": \"nom_outil\", \"arguments\": {\"param\": \"valeur\"}}\n```\n\n",
    );
    desc.push_str("Outils disponibles :\n");

    for tool in &tools {
        desc.push_str(&format!("- **{}** : {}\n", tool.name, tool.description));
        if let Some(props) = tool.parameters["properties"].as_object() {
            if !props.is_empty() {
                desc.push_str("  Paramètres : ");
                let params: Vec<String> = props
                    .iter()
                    .map(|(k, v)| {
                        let desc = v["description"].as_str().unwrap_or("");
                        format!("`{}` ({})", k, desc)
                    })
                    .collect();
                desc.push_str(&params.join(", "));
                desc.push('\n');
            }
        }
    }

    desc.push_str("\nSi tu n'as pas besoin d'outil, réponds directement en texte naturel.\n");
    desc.push_str(
        "Tu peux appeler UN outil par message. Après avoir reçu le résultat, formule ta réponse.\n",
    );
    desc
}

/// Parse a tool call from a prompt-based response.
/// Looks for ```tool_call\n{...}\n``` or raw JSON with "name" field.
pub fn parse_tool_call_from_text(text: &str) -> Option<ToolCall> {
    // Try to find ```tool_call block
    if let Some(start) = text.find("```tool_call") {
        let json_start = text[start..].find('{').map(|i| start + i)?;
        let json_end = text[json_start..]
            .find("```")
            .map(|i| json_start + i)
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
    let name = val["name"]
        .as_str()
        .or_else(|| val["tool"].as_str())
        .or_else(|| val["function"].as_str())?;

    // Validate against known tools
    let valid_tools: Vec<String> = available_tools().iter().map(|t| t.name.clone()).collect();
    if !valid_tools.contains(&name.to_string()) {
        return None;
    }

    let arguments = val
        .get("arguments")
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
        "velociraptor_list_clients" => execute_vr_list_clients(store).await,
        "velociraptor_query" => execute_vr_query(&tool_call.arguments, store).await,
        "velociraptor_hunt" => execute_vr_hunt(&tool_call.arguments, store).await,
        "velociraptor_collect" => execute_vr_collect(&tool_call.arguments, store).await,
        _ => ToolResult {
            name: tool_call.name.clone(),
            success: false,
            data: json!({"error": "Outil inconnu"}),
        },
    }
}

// ── Velociraptor tool executors ──
// Each wraps the corresponding connector function and adapts its
// `Result<Value, String>` into a `ToolResult`. The LLM sees the exact
// error message on failure so it can explain what went wrong to the
// RSSI instead of swallowing it.

async fn execute_vr_list_clients(store: &Arc<dyn Database>) -> ToolResult {
    match crate::connectors::velociraptor::tool_list_clients(store.as_ref()).await {
        Ok(data) => ToolResult {
            name: "velociraptor_list_clients".into(),
            success: true,
            data,
        },
        Err(e) => ToolResult {
            name: "velociraptor_list_clients".into(),
            success: false,
            data: json!({ "error": e }),
        },
    }
}

async fn execute_vr_query(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let vql = args["vql"].as_str().unwrap_or("").trim();
    if vql.is_empty() {
        return ToolResult {
            name: "velociraptor_query".into(),
            success: false,
            data: json!({ "error": "argument 'vql' required" }),
        };
    }
    match crate::connectors::velociraptor::tool_query(store.as_ref(), vql).await {
        Ok(data) => ToolResult {
            name: "velociraptor_query".into(),
            success: true,
            data,
        },
        Err(e) => ToolResult {
            name: "velociraptor_query".into(),
            success: false,
            data: json!({ "error": e, "vql": vql }),
        },
    }
}

async fn execute_vr_hunt(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let description = args["description"].as_str().unwrap_or("").trim();
    let artifacts: Vec<String> = args["artifacts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if description.is_empty() || artifacts.is_empty() {
        return ToolResult {
            name: "velociraptor_hunt".into(),
            success: false,
            data: json!({ "error": "'description' and 'artifacts' both required" }),
        };
    }
    match crate::connectors::velociraptor::tool_hunt(store.as_ref(), description, &artifacts).await
    {
        Ok(data) => ToolResult {
            name: "velociraptor_hunt".into(),
            success: true,
            data,
        },
        Err(e) => ToolResult {
            name: "velociraptor_hunt".into(),
            success: false,
            data: json!({ "error": e }),
        },
    }
}

async fn execute_vr_collect(args: &Value, store: &Arc<dyn Database>) -> ToolResult {
    let client_id = args["client_id"].as_str().unwrap_or("").trim();
    let artifact = args["artifact"].as_str().unwrap_or("").trim();
    if client_id.is_empty() || artifact.is_empty() {
        return ToolResult {
            name: "velociraptor_collect".into(),
            success: false,
            data: json!({ "error": "'client_id' and 'artifact' both required" }),
        };
    }
    match crate::connectors::velociraptor::tool_collect(store.as_ref(), client_id, artifact).await {
        Ok(data) => ToolResult {
            name: "velociraptor_collect".into(),
            success: true,
            data,
        },
        Err(e) => ToolResult {
            name: "velociraptor_collect".into(),
            success: false,
            data: json!({ "error": e }),
        },
    }
}

async fn execute_security_status(store: &Arc<dyn Database>) -> ToolResult {
    let situation = store
        .get_setting("_system", "security_situation")
        .await
        .ok()
        .flatten();
    let score = situation
        .as_ref()
        .and_then(|s| s["global_score"].as_f64())
        .unwrap_or(100.0);
    let alerts_count = store
        .count_alerts_filtered(None, Some("new"))
        .await
        .unwrap_or(0);
    let findings_count = store
        .count_findings_filtered(None, Some("open"), None)
        .await
        .unwrap_or(0);
    let assets_count = store.count_assets_filtered(None, None).await.unwrap_or(0);

    let label = if score >= 80.0 {
        "Situation saine"
    } else if score >= 50.0 {
        "Points d'attention"
    } else {
        "Situation dégradée"
    };

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

    let level = if severity_filter == "all" {
        None
    } else {
        Some(severity_filter)
    };

    match store.list_alerts(level, Some("new"), limit, 0).await {
        Ok(alerts) => {
            let items: Vec<Value> = alerts
                .iter()
                .map(|a| {
                    json!({
                        "title": a.title,
                        "level": a.level,
                        "hostname": a.hostname,
                        "source_ip": a.source_ip,
                        "timestamp": a.matched_at,
                        "username": a.username,
                    })
                })
                .collect();
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

    let severity = if severity_filter == "all" {
        None
    } else {
        Some(severity_filter)
    };
    let status = if status_filter == "all" {
        None
    } else {
        Some(status_filter)
    };

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
                if a.hostname
                    .as_deref()
                    .map(|h| h.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
                    || a.name.to_lowercase().contains(&query_lower)
                    || a.fqdn
                        .as_deref()
                        .map(|f| f.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
                {
                    results.push(a);
                    if results.len() >= 5 {
                        break;
                    }
                }
            }
        }
    }

    let items: Vec<Value> = results
        .iter()
        .map(|a| {
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
        })
        .collect();

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
    match store
        .list_findings(None, Some("open"), Some("ml-engine"), 10, 0)
        .await
    {
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
    let profile = store
        .get_setting("_system", "tc_config_company")
        .await
        .ok()
        .flatten();
    let nace = profile
        .as_ref()
        .and_then(|p| p["naceCode"].as_str())
        .unwrap_or("unknown");
    let sector = profile
        .as_ref()
        .and_then(|p| p["sector"].as_str())
        .unwrap_or("Non défini");
    let company = profile
        .as_ref()
        .and_then(|p| p["name"].as_str())
        .unwrap_or("Non défini");

    // Load NACE threat profile if available
    let threat_profile = store
        .get_setting("_system", &format!("nace_profile_{}", nace))
        .await
        .ok()
        .flatten();

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
    fn test_tool_requires_hitl_free_tools() {
        // Read-only tools must not require HITL license.
        for free_tool in &[
            "get_security_status",
            "get_recent_alerts",
            "get_recent_findings",
            "velociraptor_list_clients",
            "velociraptor_query",
            "velociraptor_hunt",
            "velociraptor_collect",
        ] {
            assert!(
                !tool_requires_hitl(free_tool),
                "free tool `{free_tool}` should not be HITL-gated"
            );
        }
    }

    #[test]
    fn test_tool_requires_hitl_destructive_tools() {
        for hitl_tool in &[
            "velociraptor_quarantine_endpoint",
            "velociraptor_kill_process",
            "velociraptor_isolate_host",
            "opnsense_block_ip",
            "opnsense_kill_states",
            "opnsense_quarantine_mac",
            "pfsense_block_ip",
            "fortinet_block_ip",
            "fortinet_block_url",
            "ad_disable_account",
            "ad_reset_password",
        ] {
            assert!(
                tool_requires_hitl(hitl_tool),
                "destructive tool `{hitl_tool}` should require HITL license"
            );
        }
        assert!(!tool_requires_hitl("nonexistent_tool"));
    }

    #[tokio::test]
    async fn test_check_tool_license_free_tools_pass_with_no_manager() {
        // No license manager + free tool → must succeed.
        assert!(
            check_tool_license("get_security_status", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_check_tool_license_hitl_passes_without_manager() {
        // Phase A.1 pricing pivot — HITL is free, the absence of a
        // license manager (Free instance) must NOT block destructive
        // actions anymore.
        assert!(
            check_tool_license("velociraptor_quarantine_endpoint", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_check_tool_license_hitl_passes_with_no_cert() {
        // Manager exists but no license activated — must still pass
        // post-A.1.
        let mgr = Arc::new(
            crate::licensing::LicenseManager::bootstrap(crate::licensing::LicenseClient::new(
                "https://unused.invalid",
            ))
            .await,
        );
        assert!(
            check_tool_license("opnsense_block_ip", Some(&mgr))
                .await
                .is_ok()
        );
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
            assert!(
                prompt.contains(&tool.name),
                "Prompt missing tool: {}",
                tool.name
            );
        }
        assert!(prompt.contains("tool_call"));
    }

    // The 4 Velociraptor tools must be registered AND each parameter
    // schema must declare the fields their executor reads. If any of
    // them drops out of `available_tools()` the LLM loses the capability
    // silently — the regression test catches that.
    #[test]
    fn test_velociraptor_tools_registered_with_params() {
        let tools = available_tools();
        let names: std::collections::HashSet<&str> =
            tools.iter().map(|t| t.name.as_str()).collect();
        for name in [
            "velociraptor_list_clients",
            "velociraptor_query",
            "velociraptor_hunt",
            "velociraptor_collect",
        ] {
            assert!(names.contains(name), "missing tool: {}", name);
        }
        let by_name: std::collections::HashMap<&str, &ToolDefinition> =
            tools.iter().map(|t| (t.name.as_str(), t)).collect();

        // Parameter contract: each tool's required fields match exactly
        // what the executor pulls out of tool_call.arguments.
        assert_eq!(
            by_name["velociraptor_query"].parameters["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["vql"]
        );
        let hunt_required: Vec<&str> = by_name["velociraptor_hunt"].parameters["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(hunt_required.contains(&"description") && hunt_required.contains(&"artifacts"));
        let collect_required: Vec<&str> = by_name["velociraptor_collect"].parameters["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(collect_required.contains(&"client_id") && collect_required.contains(&"artifact"));
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

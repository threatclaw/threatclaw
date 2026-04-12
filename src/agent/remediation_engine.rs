// See ADR-044: Remediation Engine — executes validated actions after HITL approval.
// All actions pass through remediation_guard before execution.

use std::sync::Arc;
use serde_json::json;
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Execute remediation for an approved incident.
/// Returns (success, message) for notification.
pub async fn execute_incident_remediation(
    store: Arc<dyn Database>,
    incident_id: i32,
    action: &str,
) -> (bool, String) {
    // Load incident
    let incident = match store.get_incident(incident_id).await {
        Ok(Some(inc)) => inc,
        _ => return (false, format!("Incident #{} not found", incident_id)),
    };

    let asset = incident["asset"].as_str().unwrap_or("");
    let title = incident["title"].as_str().unwrap_or("");

    // ADR-044 Layer 2+3: validate target through remediation guard
    if let Err(e) = crate::agent::remediation_guard::validate_remediation(action, asset) {
        tracing::error!("REMEDIATION BLOCKED: {} on {} — {}", action, asset, e);
        return (false, e);
    }

    // ADR-044 Layer 5: check HITL rate limit
    if !crate::agent::remediation_guard::can_approve_hitl() {
        let msg = "Rate limit: trop d'approbations HITL cette heure".into();
        tracing::error!("REMEDIATION BLOCKED: {}", msg);
        return (false, msg);
    }

    tracing::info!("REMEDIATION: Executing {} on {} (incident #{})", action, asset, incident_id);

    // Determine what to do based on action + available connectors
    let result = match action {
        "approve_remediate" | "block_ip" => execute_block_ip(store.as_ref(), asset, incident_id).await,
        "disable_account" => execute_disable_account(store.as_ref(), asset, incident_id).await,
        "create_ticket" => execute_create_ticket(store.as_ref(), asset, title, incident_id).await,
        _ => {
            tracing::warn!("REMEDIATION: Unknown action '{}' — marking resolved without execution", action);
            (true, format!("Incident #{} marque resolu (action: {})", incident_id, action))
        }
    };

    // Update incident with executed action
    let executed = json!({
        "action": action,
        "success": result.0,
        "message": result.1,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    // Store in incident (update executed_actions array)
    let _ = store.set_setting("_audit",
        &format!("remediation_{}_{}", incident_id, chrono::Utc::now().timestamp()),
        &executed
    ).await;

    result
}

/// Block IP on pfSense/OPNsense (reads config from DB).
async fn execute_block_ip(store: &dyn Database, asset: &str, incident_id: i32) -> (bool, String) {
    // Find the source IP from the incident alerts
    let target_ip = extract_attacker_ip(store, asset, incident_id).await;

    let target_ip = match target_ip {
        Some(ip) => ip,
        None => return (false, format!("Impossible de determiner l'IP a bloquer pour {}", asset)),
    };

    // Validate IP is not protected
    if crate::agent::remediation_guard::is_protected_target(&target_ip) {
        return (false, format!("IP {} est dans la liste d'infrastructure protegee", target_ip));
    }

    // Only block external IPs by default
    if crate::agent::ip_classifier::is_non_routable(&target_ip) {
        // Internal IP — check if isolation is allowed (rate limited)
        if !crate::agent::remediation_guard::can_isolate() {
            return (false, "Rate limit isolation interne atteint (max 3/heure)".into());
        }
        tracing::warn!("REMEDIATION: Isolating INTERNAL IP {} (incident #{})", target_ip, incident_id);
    }

    // Load pfSense/OPNsense config from DB
    let config = load_firewall_config(store).await;
    match config {
        Some((fw_type, url, user, secret, no_tls)) => {
            let result = if fw_type == "opnsense" {
                crate::connectors::remediation::opnsense_block_ip(&url, &user, &secret, &target_ip, no_tls).await
            } else {
                crate::connectors::remediation::pfsense_block_ip(&url, &user, &secret, &target_ip, no_tls).await
            };

            if result.success {
                (true, format!("IP {} bloquee sur {} (regle: {})", target_ip, fw_type,
                    result.undo_info.as_deref().unwrap_or("n/a")))
            } else {
                (false, format!("Echec blocage {} : {}", target_ip, result.message))
            }
        }
        None => (false, "Aucun firewall configure (pfSense/OPNsense)".into()),
    }
}

/// Disable AD account.
async fn execute_disable_account(store: &dyn Database, asset: &str, incident_id: i32) -> (bool, String) {
    // Get username from incident context (usually the compromised account)
    let username = extract_compromised_user(store, asset, incident_id).await;

    let username = match username {
        Some(u) => u,
        None => return (false, format!("Impossible de determiner le compte a desactiver pour {}", asset)),
    };

    // LDAP escape (ADR-044)
    let escaped_username = crate::agent::remediation_guard::ldap_escape(&username);

    // Load AD config from DB
    let ad_config = load_ad_config(store).await;
    match ad_config {
        Some((url, bind_dn, bind_pass, base_dn, no_tls)) => {
            let port: u16 = if no_tls { 389 } else { 636 };
            let result = crate::connectors::remediation::ad_disable_account(
                &url, port, &bind_dn, &bind_pass, &base_dn, &escaped_username, no_tls
            ).await;

            if result.success {
                (true, format!("Compte {} desactive dans AD", username))
            } else {
                (false, format!("Echec desactivation {} : {}", username, result.message))
            }
        }
        None => (false, "Active Directory non configure".into()),
    }
}

/// Create GLPI ticket from incident.
async fn execute_create_ticket(store: &dyn Database, asset: &str, title: &str, incident_id: i32) -> (bool, String) {
    let glpi_config = load_glpi_config(store).await;
    match glpi_config {
        Some((url, app_token, user_token)) => {
            match crate::connectors::glpi::create_ticket_from_incident(
                &url, &app_token, &user_token, incident_id, asset, title
            ).await {
                Ok(ticket_id) => (true, format!("Ticket GLPI #{} cree", ticket_id)),
                Err(e) => (false, format!("Echec creation ticket GLPI: {}", e)),
            }
        }
        None => (false, "GLPI non configure".into()),
    }
}

// ── Config loaders (read from DB settings) ──

pub(crate) async fn load_firewall_config(store: &dyn Database) -> Option<(String, String, String, String, bool)> {
    // Try pfSense first, then OPNsense
    for skill_id in &["skill-pfsense", "skill-opnsense"] {
        if let Ok(Some(val)) = store.get_setting(skill_id, "config").await {
            let url = val["url"].as_str().or(val["api_url"].as_str())?;
            let user = val["api_key"].as_str().or(val["key"].as_str()).unwrap_or("");
            let secret = val["api_secret"].as_str().or(val["secret"].as_str()).unwrap_or("");
            let no_tls = val["no_tls_verify"].as_bool().unwrap_or(true);
            let fw_type = if skill_id.contains("opn") { "opnsense" } else { "pfsense" };
            return Some((fw_type.into(), url.into(), user.into(), secret.into(), no_tls));
        }
    }
    None
}

async fn load_ad_config(store: &dyn Database) -> Option<(String, String, String, String, bool)> {
    let val = store.get_setting("skill-active-directory", "config").await.ok()??;
    let url = val["host"].as_str().or(val["url"].as_str())?;
    let bind_dn = val["bind_dn"].as_str()?;
    let bind_pass = val["bind_password"].as_str()?;
    let base_dn = val["base_dn"].as_str()?;
    let no_tls = val["no_tls_verify"].as_bool().unwrap_or(true);
    Some((url.into(), bind_dn.into(), bind_pass.into(), base_dn.into(), no_tls))
}

pub(crate) async fn load_glpi_config(store: &dyn Database) -> Option<(String, String, String)> {
    let val = store.get_setting("skill-glpi", "config").await.ok()??;
    let url = val["url"].as_str()?;
    let app_token = val["app_token"].as_str()?;
    let user_token = val["user_token"].as_str()?;
    Some((url.into(), app_token.into(), user_token.into()))
}

// ── Helpers: extract context from incident ──

/// Build a list of fallback actions for an incident based on the configured
/// remediation tools + the extractable attacker IP. Used when the L2 forensic
/// analysis didn't produce structured `proposed_actions` (legacy incidents,
/// L2 parse failure, etc.). Ensures every incident has at least some
/// executable actions on the dashboard.
pub async fn build_fallback_actions(
    store: &dyn Database,
    asset: &str,
    incident_id: i32,
) -> (Vec<serde_json::Value>, Vec<String>) {
    let mut actions: Vec<serde_json::Value> = Vec::new();
    let mut iocs: Vec<String> = Vec::new();

    // Try to extract the attacker IP from recent alerts
    let attacker_ip = extract_attacker_ip(store, asset, incident_id).await;
    if let Some(ref ip) = attacker_ip {
        iocs.push(format!("Source IP: {}", ip));
    }

    // Block IP — only if a firewall is configured AND we have an IP
    let fw_info = load_firewall_config(store).await.map(|(ty, _u, _us, _s, _t)| ty);
    match (&attacker_ip, &fw_info) {
        (Some(ip), Some(fw)) => {
            actions.push(serde_json::json!({
                "kind": "block_ip",
                "description": format!("Bloquer {} sur {} (règle ThreatClaw auto, réversible)", ip, fw),
            }));
        }
        (Some(ip), None) => {
            actions.push(serde_json::json!({
                "kind": "manual",
                "description": format!("Bloquer {} — ⚠️ aucun firewall (pfSense/OPNsense) configuré", ip),
            }));
        }
        _ => {}
    }

    // Create GLPI ticket — only if GLPI is configured
    if load_glpi_config(store).await.is_some() {
        actions.push(serde_json::json!({
            "kind": "create_ticket",
            "description": format!("Créer un ticket GLPI pour l'incident #{}", incident_id),
        }));
    }

    (actions, iocs)
}

pub async fn extract_attacker_ip(store: &dyn Database, asset: &str, _incident_id: i32) -> Option<String> {
    // Look in recent sigma alerts for source_ip on this asset
    let alerts = store.list_alerts(None, Some("new"), 50, 0).await.unwrap_or_default();
    for alert in &alerts {
        if alert.hostname.as_deref() == Some(asset) || alert.hostname.as_deref().map(|h| h.to_lowercase()) == Some(asset.to_lowercase()) {
            if let Some(ref src) = alert.source_ip {
                if !src.is_empty() && !crate::agent::ip_classifier::is_non_routable(src) {
                    return Some(src.clone());
                }
            }
        }
    }
    None
}

async fn extract_compromised_user(_store: &dyn Database, _asset: &str, _incident_id: i32) -> Option<String> {
    // TODO: extract from alert metadata (agent.name, syscheck.user, etc.)
    None
}

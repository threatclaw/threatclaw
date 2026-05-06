// See ADR-044: Remediation Engine — executes validated actions after HITL approval.
// All actions pass through remediation_guard before execution.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde_json::json;
use std::sync::Arc;

/// Execute remediation for an approved incident.
/// Returns (success, message) for notification.
///
/// Phase 9i — `cmd_id` lets the operator approve **one specific action**
/// from the panel proposed by `derive_response_actions`. Pass `None` to
/// keep the legacy behaviour (single-action incidents driven by `action`,
/// e.g. "approve" → block_ip). Pass `Some("velociraptor_isolate_host")` to
/// execute exactly that. The `cmd_id` matching is exhaustive and falls
/// back to the action-based switch when unrecognised so older buttons
/// keep working.
pub async fn execute_incident_remediation(
    store: Arc<dyn Database>,
    incident_id: i32,
    action: &str,
) -> (bool, String) {
    execute_incident_remediation_for(store, incident_id, action, None).await
}

/// Phase 9i — granular variant that targets a specific `cmd_id`. The
/// public `execute_incident_remediation` keeps a single-arg signature for
/// existing callers (Slack/Discord URL buttons, legacy approve-all UI);
/// this is what the new per-action HITL handler invokes.
pub async fn execute_incident_remediation_for(
    store: Arc<dyn Database>,
    incident_id: i32,
    action: &str,
    cmd_id: Option<&str>,
) -> (bool, String) {
    // Load incident
    let incident = match store.get_incident(incident_id).await {
        Ok(Some(inc)) => inc,
        _ => return (false, format!("Incident #{} not found", incident_id)),
    };

    let asset = incident["asset"].as_str().unwrap_or("");
    let title = incident["title"].as_str().unwrap_or("");

    // ADR-044 Layer 2+3: validate target through remediation guard
    let guard_subject = cmd_id.unwrap_or(action);
    if let Err(e) = crate::agent::remediation_guard::validate_remediation(guard_subject, asset) {
        tracing::error!(
            "REMEDIATION BLOCKED: {} on {} — {}",
            guard_subject,
            asset,
            e
        );
        return (false, e);
    }

    // ADR-044 Layer 5: check HITL rate limit
    if !crate::agent::remediation_guard::can_approve_hitl() {
        let msg = "Rate limit: trop d'approbations HITL cette heure".into();
        tracing::error!("REMEDIATION BLOCKED: {}", msg);
        return (false, msg);
    }

    tracing::info!(
        "REMEDIATION: Executing action='{}' cmd_id={:?} on {} (incident #{})",
        action,
        cmd_id,
        asset,
        incident_id
    );

    // Phase 9i — when an explicit cmd_id is supplied, match on it exactly.
    // Each `cmd_id` belongs to the canonical taxonomy in
    // `agent::incident_action::ActionKind`. Multiple vendor cmd_ids
    // (`opnsense_block_ip`, `fortinet_block_ip`...) collapse to the same
    // execution path because `execute_block_ip` re-reads the active
    // firewall config from the DB.
    let dispatched = match cmd_id {
        Some("opnsense_block_ip")
        | Some("fortinet_block_ip")
        | Some("pfsense_block_ip")
        | Some("mikrotik_block_ip")
        | Some("proxmox_block_ip") => {
            Some(execute_block_ip(store.as_ref(), asset, incident_id).await)
        }
        Some("velociraptor_isolate_host") | Some("edr_isolate_host") => {
            Some(execute_isolate_host(store.as_ref(), asset, incident_id).await)
        }
        Some("velociraptor_kill_process") | Some("edr_kill_process") => {
            Some(execute_kill_process(store.as_ref(), asset, incident_id).await)
        }
        Some("ad_disable_user")
        | Some("azuread_disable_user")
        | Some("keycloak_disable_user")
        | Some("authentik_disable_user") => {
            Some(execute_disable_account(store.as_ref(), asset, incident_id).await)
        }
        Some("ad_reset_password")
        | Some("azuread_reset_password")
        | Some("keycloak_reset_password") => {
            Some(execute_reset_password(store.as_ref(), asset, incident_id).await)
        }
        Some("manual") => Some((
            true,
            format!(
                "Action manuelle marquée résolue (incident #{} — pas d'automation)",
                incident_id
            ),
        )),
        Some(unknown) => {
            tracing::warn!(
                "REMEDIATION: cmd_id='{}' has no Phase 9i handler — falling back to action match",
                unknown
            );
            None
        }
        None => None,
    };

    let result = if let Some(r) = dispatched {
        r
    } else {
        // Legacy action-based dispatch (URL buttons, approve-all flow).
        match action {
            "approve_remediate" | "block_ip" => {
                execute_block_ip(store.as_ref(), asset, incident_id).await
            }
            "disable_account" => execute_disable_account(store.as_ref(), asset, incident_id).await,
            "kill_states" => execute_kill_states(store.as_ref(), asset, incident_id).await,
            "reset_password" => execute_reset_password(store.as_ref(), asset, incident_id).await,
            "quarantine_endpoint" | "velociraptor_quarantine_endpoint" => {
                execute_quarantine_endpoint(store.as_ref(), asset, incident_id).await
            }
            "isolate_host" | "velociraptor_isolate_host" => {
                execute_isolate_host(store.as_ref(), asset, incident_id).await
            }
            "kill_process" | "velociraptor_kill_process" => {
                execute_kill_process(store.as_ref(), asset, incident_id).await
            }
            "create_ticket" => {
                execute_create_ticket(store.as_ref(), asset, title, incident_id).await
            }
            _ => {
                tracing::warn!(
                    "REMEDIATION: Unknown action '{}' — marking resolved without execution",
                    action
                );
                (
                    true,
                    format!(
                        "Incident #{} marque resolu (action: {})",
                        incident_id, action
                    ),
                )
            }
        }
    };

    // Update incident with executed action
    let executed = json!({
        "action": action,
        "cmd_id": cmd_id,
        "success": result.0,
        "message": result.1,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    // Store in incident (update executed_actions array)
    let _ = store
        .set_setting(
            "_audit",
            &format!(
                "remediation_{}_{}",
                incident_id,
                chrono::Utc::now().timestamp()
            ),
            &executed,
        )
        .await;

    result
}

/// Block IP on pfSense/OPNsense (reads config from DB).
async fn execute_block_ip(store: &dyn Database, asset: &str, incident_id: i32) -> (bool, String) {
    // Find the source IP from the incident alerts
    let target_ip = extract_attacker_ip(store, asset, incident_id).await;

    let target_ip = match target_ip {
        Some(ip) => ip,
        None => {
            return (
                false,
                format!("Impossible de determiner l'IP a bloquer pour {}", asset),
            );
        }
    };

    // Validate IP is not protected
    if crate::agent::remediation_guard::is_protected_target(&target_ip) {
        return (
            false,
            format!(
                "IP {} est dans la liste d'infrastructure protegee",
                target_ip
            ),
        );
    }

    // Only block external IPs by default
    if crate::agent::ip_classifier::is_non_routable(&target_ip) {
        // Internal IP — check if isolation is allowed (rate limited)
        if !crate::agent::remediation_guard::can_isolate() {
            return (
                false,
                "Rate limit isolation interne atteint (max 3/heure)".into(),
            );
        }
        tracing::warn!(
            "REMEDIATION: Isolating INTERNAL IP {} (incident #{})",
            target_ip,
            incident_id
        );
    }

    // Load pfSense / OPNsense / FortiGate config from DB.
    let config = load_firewall_config(store).await;
    match config {
        Some((fw_type, url, user, secret, no_tls)) => {
            let result = match fw_type.as_str() {
                "opnsense" => {
                    crate::connectors::remediation::opnsense_block_ip(
                        &url, &user, &secret, &target_ip, no_tls,
                    )
                    .await
                }
                "fortinet" => {
                    let cfg = crate::connectors::fortinet::FortinetConfig {
                        url: url.clone(),
                        api_key: user.clone(),
                        no_tls_verify: no_tls,
                        cursor_user_event: None,
                        cursor_system_event: None,
                        cursor_forward_traffic: None,
                        cursor_utm_virus: None,
                        cursor_utm_ips: None,
                        cursor_utm_webfilter: None,
                        cursor_utm_app_ctrl: None,
                    };
                    match crate::connectors::fortinet::block_ip(&cfg, &target_ip).await {
                        Ok(v) => crate::connectors::remediation::RemediationResult {
                            success: true,
                            action: "fortinet_block_ip".into(),
                            target: target_ip.clone(),
                            message: format!(
                                "Quarantined via {}",
                                v["method"].as_str().unwrap_or("monitor.user.banned")
                            ),
                            reversible: true,
                            undo_info: v["undo"].as_str().map(String::from),
                        },
                        Err(e) => crate::connectors::remediation::RemediationResult {
                            success: false,
                            action: "fortinet_block_ip".into(),
                            target: target_ip.clone(),
                            message: e,
                            reversible: true,
                            undo_info: None,
                        },
                    }
                }
                _ => {
                    crate::connectors::remediation::pfsense_block_ip(
                        &url, &user, &secret, &target_ip, no_tls,
                    )
                    .await
                }
            };

            if result.success {
                (
                    true,
                    format!(
                        "IP {} bloquee sur {} (regle: {})",
                        target_ip,
                        fw_type,
                        result.undo_info.as_deref().unwrap_or("n/a")
                    ),
                )
            } else {
                (
                    false,
                    format!("Echec blocage {} : {}", target_ip, result.message),
                )
            }
        }
        None => (
            false,
            "Aucun firewall configure (pfSense / OPNsense / FortiGate)".into(),
        ),
    }
}

/// Kill active pf states for the attacker IP on the lab firewall.
/// Used in tandem with `block_ip` when the operator wants to cut
/// in-flight connections too, not just future packets.
async fn execute_kill_states(
    store: &dyn Database,
    asset: &str,
    incident_id: i32,
) -> (bool, String) {
    let target_ip = match extract_attacker_ip(store, asset, incident_id).await {
        Some(ip) => ip,
        None => {
            return (
                false,
                format!("Impossible de determiner l'IP source pour {}", asset),
            );
        }
    };
    if crate::agent::remediation_guard::is_protected_target(&target_ip) {
        return (false, format!("IP {} dans la liste protegee", target_ip));
    }
    match load_firewall_config(store).await {
        Some((fw_type, url, user, secret, no_tls)) if fw_type == "opnsense" => {
            let result = crate::connectors::remediation::opnsense_kill_states(
                &url, &user, &secret, &target_ip, no_tls,
            )
            .await;
            if result.success {
                (true, result.message)
            } else {
                (false, format!("Echec kill_states : {}", result.message))
            }
        }
        Some(_) => (
            false,
            "kill_states n'est pas implémenté pour pfSense (OPNsense uniquement)".into(),
        ),
        None => (false, "Aucun firewall configure (OPNsense)".into()),
    }
}

/// Quarantine an endpoint via Velociraptor — installs host-firewall
/// rules that block all network traffic except the Velociraptor
/// frontend, so the agent stays controllable while malware loses C2
/// and lateral movement.
async fn execute_quarantine_endpoint(
    store: &dyn Database,
    asset: &str,
    _incident_id: i32,
) -> (bool, String) {
    let client_id = match resolve_velociraptor_client_id(store, asset).await {
        Ok(id) => id,
        Err(msg) => return (false, msg),
    };
    match crate::connectors::velociraptor::quarantine_endpoint(store, &client_id).await {
        Ok(v) => {
            let flow = v["flow_id"].as_str().unwrap_or("?");
            (
                true,
                format!("Endpoint {} mis en quarantaine (flow {})", asset, flow),
            )
        }
        Err(e) => (false, format!("Echec quarantine_endpoint : {}", e)),
    }
}

/// Same as `quarantine_endpoint` but surfaced as a separate UI action
/// for operators who think of it as "block egress" rather than full
/// quarantine. Wires to the same Velociraptor artifact.
async fn execute_isolate_host(
    store: &dyn Database,
    asset: &str,
    _incident_id: i32,
) -> (bool, String) {
    let client_id = match resolve_velociraptor_client_id(store, asset).await {
        Ok(id) => id,
        Err(msg) => return (false, msg),
    };
    match crate::connectors::velociraptor::isolate_host(store, &client_id).await {
        Ok(v) => {
            let flow = v["flow_id"].as_str().unwrap_or("?");
            (true, format!("Endpoint {} isolé (flow {})", asset, flow))
        }
        Err(e) => (false, format!("Echec isolate_host : {}", e)),
    }
}

/// Kill a suspect process on the endpoint. The process target is
/// extracted from recent Wazuh alerts on this asset (NewProcessName /
/// Image / process.name), preferring the most recent.
async fn execute_kill_process(
    store: &dyn Database,
    asset: &str,
    incident_id: i32,
) -> (bool, String) {
    let client_id = match resolve_velociraptor_client_id(store, asset).await {
        Ok(id) => id,
        Err(msg) => return (false, msg),
    };
    let target = match extract_suspect_process(store, asset, incident_id).await {
        Some(p) => p,
        None => {
            return (
                false,
                format!(
                    "Impossible de determiner le processus a terminer pour {} (aucune alerte avec NewProcessName/Image)",
                    asset
                ),
            );
        }
    };
    match crate::connectors::velociraptor::kill_process(store, &client_id, &target).await {
        Ok(v) => {
            let flow = v["flow_id"].as_str().unwrap_or("?");
            (
                true,
                format!(
                    "Processus '{}' terminé sur {} (flow {})",
                    target, asset, flow
                ),
            )
        }
        Err(e) => (false, format!("Echec kill_process : {}", e)),
    }
}

/// Look up the Velociraptor client_id for `asset` by listing all
/// clients and matching on hostname/fqdn (case-insensitive). Returns
/// a clear error if Velociraptor isn't configured or the asset isn't
/// known to it.
async fn resolve_velociraptor_client_id(
    store: &dyn Database,
    asset: &str,
) -> Result<String, String> {
    let listing = crate::connectors::velociraptor::tool_list_clients(store)
        .await
        .map_err(|e| format!("Velociraptor list_clients: {}", e))?;
    let asset_lc = asset.to_lowercase();
    let clients = listing["clients"].as_array().cloned().unwrap_or_default();
    for c in &clients {
        let hostname = c["hostname"].as_str().unwrap_or("").to_lowercase();
        let fqdn = c["fqdn"].as_str().unwrap_or("").to_lowercase();
        if !hostname.is_empty() && hostname == asset_lc {
            return Ok(c["client_id"].as_str().unwrap_or_default().to_string());
        }
        if !fqdn.is_empty() && (fqdn == asset_lc || fqdn.starts_with(&format!("{}.", asset_lc))) {
            return Ok(c["client_id"].as_str().unwrap_or_default().to_string());
        }
    }
    Err(format!(
        "Asset '{}' non trouvé côté Velociraptor (l'agent n'est peut-être pas installé ou pas synchronisé)",
        asset
    ))
}

/// Extract a process name (or PID) from recent alerts on `asset`. Looks
/// at Windows event metadata and Sysmon-style fields commonly stored
/// in `matched_fields` by the Wazuh import path.
async fn extract_suspect_process(
    store: &dyn Database,
    asset: &str,
    _incident_id: i32,
) -> Option<String> {
    let alerts = store
        .list_alerts(None, None, 50, 0)
        .await
        .unwrap_or_default();
    let asset_lc = asset.to_lowercase();
    for alert in &alerts {
        let host_match = alert
            .hostname
            .as_deref()
            .map(|h| h.to_lowercase() == asset_lc)
            .unwrap_or(false);
        if !host_match {
            continue;
        }
        let fields = match alert.matched_fields.as_ref() {
            Some(v) => v,
            None => continue,
        };
        for path in [
            ("data", "win", "eventdata", "NewProcessName"),
            ("data", "win", "eventdata", "Image"),
            ("data", "win", "eventdata", "ProcessName"),
        ] {
            if let Some(val) = fields[path.0][path.1][path.2][path.3].as_str() {
                if let Some(name) = process_name_only(val) {
                    return Some(name);
                }
            }
        }
        if let Some(val) = fields["process"]["name"].as_str() {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
        if let Some(val) = fields["data"]["process"].as_str() {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Strip the directory portion of a Windows path so `C:\Users\foo\evil.exe`
/// becomes `evil.exe`. Velociraptor's ProcessKill matches by basename
/// when given a name, which is what operators expect.
fn process_name_only(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let slash = trimmed.rfind(['\\', '/']);
    let name = match slash {
        Some(idx) => &trimmed[idx + 1..],
        None => trimmed,
    };
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Force a password reset on an AD account at next login. Pairs with
/// `disable_account` for compromised credentials — disable while the
/// IR is in progress, force reset before re-enabling.
async fn execute_reset_password(
    store: &dyn Database,
    asset: &str,
    incident_id: i32,
) -> (bool, String) {
    let username = match extract_compromised_user(store, asset, incident_id).await {
        Some(u) => u,
        None => {
            return (
                false,
                format!("Impossible de determiner le compte concerne pour {}", asset),
            );
        }
    };
    let escaped = crate::agent::remediation_guard::ldap_escape(&username);
    match load_ad_config(store).await {
        Some((url, bind_dn, bind_pass, base_dn, no_tls)) => {
            let port: u16 = if no_tls { 389 } else { 636 };
            let result = crate::connectors::remediation::ad_reset_password(
                &url, port, &bind_dn, &bind_pass, &base_dn, &escaped, no_tls,
            )
            .await;
            if result.success {
                (true, result.message)
            } else {
                (false, format!("Echec reset_password : {}", result.message))
            }
        }
        None => (false, "Active Directory non configure".into()),
    }
}

/// Disable AD account.
async fn execute_disable_account(
    store: &dyn Database,
    asset: &str,
    incident_id: i32,
) -> (bool, String) {
    // Get username from incident context (usually the compromised account)
    let username = extract_compromised_user(store, asset, incident_id).await;

    let username = match username {
        Some(u) => u,
        None => {
            return (
                false,
                format!(
                    "Impossible de determiner le compte a desactiver pour {}",
                    asset
                ),
            );
        }
    };

    // LDAP escape (ADR-044)
    let escaped_username = crate::agent::remediation_guard::ldap_escape(&username);

    // Load AD config from DB
    let ad_config = load_ad_config(store).await;
    match ad_config {
        Some((url, bind_dn, bind_pass, base_dn, no_tls)) => {
            let port: u16 = if no_tls { 389 } else { 636 };
            let result = crate::connectors::remediation::ad_disable_account(
                &url,
                port,
                &bind_dn,
                &bind_pass,
                &base_dn,
                &escaped_username,
                no_tls,
            )
            .await;

            if result.success {
                (true, format!("Compte {} desactive dans AD", username))
            } else {
                (
                    false,
                    format!("Echec desactivation {} : {}", username, result.message),
                )
            }
        }
        None => (false, "Active Directory non configure".into()),
    }
}

/// Create GLPI ticket from incident.
async fn execute_create_ticket(
    store: &dyn Database,
    asset: &str,
    title: &str,
    incident_id: i32,
) -> (bool, String) {
    let glpi_config = load_glpi_config(store).await;
    match glpi_config {
        Some((url, app_token, user_token)) => {
            match crate::connectors::glpi::create_ticket_from_incident(
                &url,
                &app_token,
                &user_token,
                incident_id,
                asset,
                title,
            )
            .await
            {
                Ok(ticket_id) => (true, format!("Ticket GLPI #{} cree", ticket_id)),
                Err(e) => (false, format!("Echec creation ticket GLPI: {}", e)),
            }
        }
        None => (false, "GLPI non configure".into()),
    }
}

// ── Config loaders (read from DB settings) ──

pub(crate) async fn load_firewall_config(
    store: &dyn Database,
) -> Option<(String, String, String, String, bool)> {
    // Probe pfSense → OPNsense → FortiGate. Fortinet uses a single token
    // (api_key) so the "user" field carries it and "secret" is empty —
    // the dispatch in execute_block_ip rebuilds a FortinetConfig from
    // that shape.
    for skill_id in &["skill-pfsense", "skill-opnsense", "skill-fortinet"] {
        if let Ok(Some(val)) = store.get_setting(skill_id, "config").await {
            let url = match val["url"].as_str().or(val["api_url"].as_str()) {
                Some(u) => u,
                None => continue,
            };
            let no_tls = val["no_tls_verify"].as_bool().unwrap_or(true);
            let (fw_type, user, secret) = if *skill_id == "skill-fortinet" {
                let token = val["api_key"].as_str().unwrap_or("");
                ("fortinet", token, "")
            } else if *skill_id == "skill-opnsense" {
                (
                    "opnsense",
                    val["auth_user"]
                        .as_str()
                        .or(val["api_key"].as_str())
                        .or(val["key"].as_str())
                        .unwrap_or(""),
                    val["auth_secret"]
                        .as_str()
                        .or(val["api_secret"].as_str())
                        .or(val["secret"].as_str())
                        .unwrap_or(""),
                )
            } else {
                (
                    "pfsense",
                    val["api_key"]
                        .as_str()
                        .or(val["key"].as_str())
                        .unwrap_or(""),
                    val["api_secret"]
                        .as_str()
                        .or(val["secret"].as_str())
                        .unwrap_or(""),
                )
            };
            return Some((
                fw_type.into(),
                url.into(),
                user.into(),
                secret.into(),
                no_tls,
            ));
        }
    }
    None
}

async fn load_ad_config(store: &dyn Database) -> Option<(String, String, String, String, bool)> {
    let val = store
        .get_setting("skill-active-directory", "config")
        .await
        .ok()??;
    let url = val["host"].as_str().or(val["url"].as_str())?;
    let bind_dn = val["bind_dn"].as_str()?;
    let bind_pass = val["bind_password"].as_str()?;
    let base_dn = val["base_dn"].as_str()?;
    let no_tls = val["no_tls_verify"].as_bool().unwrap_or(true);
    Some((
        url.into(),
        bind_dn.into(),
        bind_pass.into(),
        base_dn.into(),
        no_tls,
    ))
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
    let fw_info = load_firewall_config(store)
        .await
        .map(|(ty, _u, _us, _s, _t)| ty);
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

pub async fn extract_attacker_ip(
    store: &dyn Database,
    asset: &str,
    _incident_id: i32,
) -> Option<String> {
    // Look in recent sigma alerts for source_ip on this asset
    let alerts = store
        .list_alerts(None, Some("new"), 50, 0)
        .await
        .unwrap_or_default();
    for alert in &alerts {
        if alert.hostname.as_deref() == Some(asset)
            || alert.hostname.as_deref().map(|h| h.to_lowercase()) == Some(asset.to_lowercase())
        {
            if let Some(ref src) = alert.source_ip {
                if !src.is_empty() && !crate::agent::ip_classifier::is_non_routable(src) {
                    return Some(src.clone());
                }
            }
        }
    }
    None
}

/// Extract the username most likely associated with the incident on `asset`.
///
/// Reads recent sigma alerts (Wazuh-fed) for this hostname and returns the
/// first plausible human account. Skips machine accounts (`HOST$`), the
/// SYSTEM pseudo-account, and ANONYMOUS LOGON — none of those should be
/// targeted by `disable_account` or `reset_password`.
///
/// Username normalization mirrors what the Wazuh connector applies on the
/// way in (drop `DOMAIN\` prefix, drop `@REALM` suffix, lowercase) so the
/// value can be passed straight to LDAP modify on the AD bind DN.
pub async fn extract_compromised_user(
    store: &dyn Database,
    asset: &str,
    _incident_id: i32,
) -> Option<String> {
    let alerts = store
        .list_alerts(None, None, 100, 0)
        .await
        .unwrap_or_default();
    let asset_lc = asset.to_lowercase();
    for alert in &alerts {
        let host_match = alert
            .hostname
            .as_deref()
            .map(|h| h.to_lowercase() == asset_lc)
            .unwrap_or(false);
        if !host_match {
            continue;
        }
        if let Some(raw) = alert.username.as_deref() {
            if let Some(normalized) = normalize_account_name(raw) {
                return Some(normalized);
            }
        }
    }
    None
}

/// Normalize a raw username from a SIEM alert into a sAMAccountName-style
/// identifier suitable for AD operations. Returns `None` if the value is a
/// machine/system account that must not be targeted by remediation.
fn normalize_account_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return None;
    }
    // Strip Windows DOMAIN\user prefix
    let no_domain = trimmed.rsplit_once('\\').map(|(_, u)| u).unwrap_or(trimmed);
    // Strip Kerberos UPN @realm
    let no_realm = no_domain
        .split_once('@')
        .map(|(u, _)| u)
        .unwrap_or(no_domain);
    let lc = no_realm.to_ascii_lowercase();
    // Skip machine accounts (HOST$) and well-known pseudo-accounts.
    if lc.ends_with('$') {
        return None;
    }
    if matches!(
        lc.as_str(),
        "system" | "anonymous logon" | "anonymous" | "local service" | "network service"
    ) {
        return None;
    }
    Some(lc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_domain_and_realm() {
        assert_eq!(
            normalize_account_name("CORP\\jdoe").as_deref(),
            Some("jdoe")
        );
        assert_eq!(
            normalize_account_name("jdoe@CORP.LOCAL").as_deref(),
            Some("jdoe")
        );
        assert_eq!(normalize_account_name("JDoe").as_deref(), Some("jdoe"));
    }

    #[test]
    fn process_name_only_strips_paths() {
        assert_eq!(
            process_name_only("C:\\Users\\admin\\evil.exe").as_deref(),
            Some("evil.exe")
        );
        assert_eq!(
            process_name_only("/usr/bin/suspicious").as_deref(),
            Some("suspicious")
        );
        assert_eq!(
            process_name_only("powershell.exe").as_deref(),
            Some("powershell.exe")
        );
        assert_eq!(process_name_only("  cmd.exe  ").as_deref(), Some("cmd.exe"));
        assert!(process_name_only("").is_none());
    }

    #[test]
    fn normalize_rejects_machine_and_system() {
        assert!(normalize_account_name("WS01$").is_none());
        assert!(normalize_account_name("CORP\\WS01$").is_none());
        assert!(normalize_account_name("SYSTEM").is_none());
        assert!(normalize_account_name("ANONYMOUS LOGON").is_none());
        assert!(normalize_account_name("-").is_none());
        assert!(normalize_account_name("").is_none());
    }
}

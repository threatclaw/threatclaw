//! Remediation actions (HITL required). See ADR-031.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Result of a remediation action.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationResult {
    pub action: String,
    pub target: String,
    pub success: bool,
    pub message: String,
    pub reversible: bool,
    pub undo_info: Option<String>,
}

// ══════════════════════════════════════════════════════════
// pfSense / OPNsense — Block IP
// ══════════════════════════════════════════════════════════

/// Block an IP address on pfSense via the REST API.
/// Creates a firewall rule that drops all traffic from the IP.
pub async fn pfsense_block_ip(
    fw_url: &str,
    auth_user: &str,
    auth_secret: &str,
    ip_to_block: &str,
    no_tls_verify: bool,
) -> RemediationResult {
    let client = match Client::builder()
        .danger_accept_invalid_certs(no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RemediationResult {
                action: "pfsense_block_ip".into(),
                target: ip_to_block.into(),
                success: false,
                message: format!("HTTP client error: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    // Validate IP format (prevent injection)
    if !is_valid_ip(ip_to_block) {
        return RemediationResult {
            action: "pfsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: "Invalid IP format".into(),
            reversible: false,
            undo_info: None,
        };
    }

    // pfSense REST API v2: POST /api/v2/firewall/rule
    let url = format!("{}/api/v2/firewall/rule", fw_url);
    let rule = serde_json::json!({
        "type": "block",
        "interface": "wan",
        "ipprotocol": "inet",
        "protocol": "any",
        "source": ip_to_block,
        "destination": "any",
        "descr": format!("ThreatClaw auto-block: {}", ip_to_block),
        "top": true,
        "apply": true
    });

    let resp = match client
        .post(&url)
        .basic_auth(auth_user, Some(auth_secret))
        .json(&rule)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return RemediationResult {
                action: "pfsense_block_ip".into(),
                target: ip_to_block.into(),
                success: false,
                message: format!("API request failed: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if status.is_success() {
        let rule_id = body["data"]["id"].as_i64().unwrap_or(0);
        tracing::info!(
            "REMEDIATION: Blocked IP {} on pfSense (rule #{})",
            ip_to_block,
            rule_id
        );
        RemediationResult {
            action: "pfsense_block_ip".into(),
            target: ip_to_block.into(),
            success: true,
            message: format!(
                "IP {} bloquee sur le firewall (regle #{})",
                ip_to_block, rule_id
            ),
            reversible: true,
            undo_info: Some(format!(
                "DELETE {}/api/v2/firewall/rule/{}",
                fw_url, rule_id
            )),
        }
    } else {
        RemediationResult {
            action: "pfsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: format!("pfSense API error: HTTP {} — {:?}", status, body),
            reversible: true,
            undo_info: None,
        }
    }
}

/// Block IP on OPNsense via its API.
pub async fn opnsense_block_ip(
    fw_url: &str,
    api_key: &str,
    api_secret: &str,
    ip_to_block: &str,
    no_tls_verify: bool,
) -> RemediationResult {
    let client = match Client::builder()
        .danger_accept_invalid_certs(no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RemediationResult {
                action: "opnsense_block_ip".into(),
                target: ip_to_block.into(),
                success: false,
                message: format!("HTTP client error: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    if !is_valid_ip(ip_to_block) {
        return RemediationResult {
            action: "opnsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: "Invalid IP format".into(),
            reversible: false,
            undo_info: None,
        };
    }

    // OPNsense: POST /api/firewall/filter/addRule + POST /api/firewall/filter/apply
    let url = format!("{}/api/firewall/filter/addRule", fw_url);
    let rule = serde_json::json!({
        "rule": {
            "enabled": "1",
            "action": "block",
            "quick": "1",
            "interface": "wan",
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": ip_to_block,
            "destination_net": "any",
            "description": format!("ThreatClaw auto-block: {}", ip_to_block)
        }
    });

    let resp = match client
        .post(&url)
        .basic_auth(api_key, Some(api_secret))
        .json(&rule)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return RemediationResult {
                action: "opnsense_block_ip".into(),
                target: ip_to_block.into(),
                success: false,
                message: format!("OPNsense API error: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if status.is_success() {
        let uuid = body["uuid"].as_str().unwrap_or("");

        // Apply the rule
        let apply_url = format!("{}/api/firewall/filter/apply", fw_url);
        let _ = client
            .post(&apply_url)
            .basic_auth(api_key, Some(api_secret))
            .send()
            .await;

        tracing::info!(
            "REMEDIATION: Blocked IP {} on OPNsense (uuid: {})",
            ip_to_block,
            uuid
        );
        RemediationResult {
            action: "opnsense_block_ip".into(),
            target: ip_to_block.into(),
            success: true,
            message: format!("IP {} bloquee sur OPNsense", ip_to_block),
            reversible: true,
            undo_info: Some(format!(
                "DELETE {}/api/firewall/filter/delRule/{}",
                fw_url, uuid
            )),
        }
    } else {
        RemediationResult {
            action: "opnsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: format!("OPNsense error: HTTP {}", status),
            reversible: true,
            undo_info: None,
        }
    }
}

// ══════════════════════════════════════════════════════════
// Active Directory — Disable Account
// ══════════════════════════════════════════════════════════

/// Disable a compromised account in Active Directory via LDAP.
/// Sets the ACCOUNTDISABLE flag in userAccountControl.
pub async fn ad_disable_account(
    host: &str,
    port: u16,
    bind_dn: &str,
    bind_pw: &str,
    base_dn: &str,
    username_to_disable: &str,
    no_tls_verify: bool,
) -> RemediationResult {
    use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope};

    let url = if port == 636 {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(15))
        .set_no_tls_verify(no_tls_verify);

    let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, &url).await {
        Ok(c) => c,
        Err(e) => {
            return RemediationResult {
                action: "ad_disable_account".into(),
                target: username_to_disable.into(),
                success: false,
                message: format!("LDAP connection failed: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    tokio::spawn(async move {
        let _ = conn.drive().await;
    });

    if let Err(e) = ldap
        .simple_bind(bind_dn, bind_pw)
        .await
        .and_then(|res| res.success().map(|_| ()))
    {
        return RemediationResult {
            action: "ad_disable_account".into(),
            target: username_to_disable.into(),
            success: false,
            message: format!("LDAP bind failed: {}", e),
            reversible: true,
            undo_info: None,
        };
    }

    // Find the user's DN
    let filter = format!(
        "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
        username_to_disable
    );
    let (results, _) = match ldap
        .search(
            base_dn,
            Scope::Subtree,
            &filter,
            vec!["distinguishedName", "userAccountControl"],
        )
        .await
        .and_then(|res| res.success())
    {
        Ok(r) => r,
        Err(e) => {
            return RemediationResult {
                action: "ad_disable_account".into(),
                target: username_to_disable.into(),
                success: false,
                message: format!("LDAP search failed: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    if results.is_empty() {
        let _ = ldap.unbind().await;
        return RemediationResult {
            action: "ad_disable_account".into(),
            target: username_to_disable.into(),
            success: false,
            message: format!("Utilisateur '{}' non trouve dans l'AD", username_to_disable),
            reversible: false,
            undo_info: None,
        };
    }

    let entry = ldap3::SearchEntry::construct(results.into_iter().next().unwrap());
    let user_dn = &entry.dn;

    // Get current userAccountControl
    let current_uac = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(512); // 512 = NORMAL_ACCOUNT

    // Set ACCOUNTDISABLE flag (0x0002)
    let new_uac = current_uac | 0x0002;

    let new_uac_str = new_uac.to_string();
    let mods = vec![Mod::Replace(
        "userAccountControl",
        std::collections::HashSet::from([new_uac_str.as_str()]),
    )];

    match ldap
        .modify(user_dn, mods)
        .await
        .and_then(|res| res.success().map(|_| ()))
    {
        Ok(_) => {
            tracing::warn!(
                "REMEDIATION: Disabled AD account '{}' (DN: {})",
                username_to_disable,
                user_dn
            );
            let _ = ldap.unbind().await;
            RemediationResult {
                action: "ad_disable_account".into(),
                target: username_to_disable.into(),
                success: true,
                message: format!(
                    "Compte '{}' desactive dans Active Directory",
                    username_to_disable
                ),
                reversible: true,
                undo_info: Some(format!(
                    "Re-enable: set userAccountControl={} on {}",
                    current_uac, user_dn
                )),
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            RemediationResult {
                action: "ad_disable_account".into(),
                target: username_to_disable.into(),
                success: false,
                message: format!(
                    "Echec desactivation: {} — le compte de service a-t-il les droits ?",
                    e
                ),
                reversible: true,
                undo_info: None,
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
// OPNsense — Kill active connection states (C26a)
// ══════════════════════════════════════════════════════════

/// Terminate every pf state (active connection) involving a given IP,
/// in either direction. Pairs with `opnsense_block_ip` to cut both the
/// future packets (rule) AND the in-flight ones (states). Reversible:
/// blocked traffic resumes naturally if the operator rolls back the
/// firewall rule.
///
/// OPNsense API: `POST /api/diagnostics/firewall/kill_states`
/// Body: `{"filter": "<ip>"}` — accepts an IP / CIDR / ipfw-style filter.
pub async fn opnsense_kill_states(
    fw_url: &str,
    api_key: &str,
    api_secret: &str,
    ip_to_kill: &str,
    no_tls_verify: bool,
) -> RemediationResult {
    if !is_valid_ip(ip_to_kill) {
        return RemediationResult {
            action: "opnsense_kill_states".into(),
            target: ip_to_kill.into(),
            success: false,
            message: "Invalid IP format".into(),
            reversible: false,
            undo_info: None,
        };
    }

    let client = match Client::builder()
        .danger_accept_invalid_certs(no_tls_verify)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RemediationResult {
                action: "opnsense_kill_states".into(),
                target: ip_to_kill.into(),
                success: false,
                message: format!("HTTP client error: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    let url = format!("{}/api/diagnostics/firewall/kill_states", fw_url);
    let body = serde_json::json!({"filter": ip_to_kill});
    let resp = match client
        .post(&url)
        .basic_auth(api_key, Some(api_secret))
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return RemediationResult {
                action: "opnsense_kill_states".into(),
                target: ip_to_kill.into(),
                success: false,
                message: format!("OPNsense API error: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    let status = resp.status();
    if status.is_success() {
        let killed = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("dropped").and_then(|n| n.as_i64()))
            .unwrap_or(0);
        tracing::warn!(
            "REMEDIATION: Killed {} states for {} on OPNsense",
            killed,
            ip_to_kill
        );
        RemediationResult {
            action: "opnsense_kill_states".into(),
            target: ip_to_kill.into(),
            success: true,
            message: format!("{} états actifs terminés pour {}", killed, ip_to_kill),
            reversible: false, // a killed state is gone — the next packet rebuilds one
            undo_info: None,
        }
    } else {
        RemediationResult {
            action: "opnsense_kill_states".into(),
            target: ip_to_kill.into(),
            success: false,
            message: format!("OPNsense kill_states refusé : HTTP {}", status),
            reversible: true,
            undo_info: None,
        }
    }
}

// ══════════════════════════════════════════════════════════
// OPNsense — Quarantine MAC via firewall alias
// ══════════════════════════════════════════════════════════

/// Quarantine a MAC address by adding it to a firewall alias
/// `TC_QUARANTINE_MACS` (auto-created on first call). The admin attaches
/// that alias to a deny rule on the LAN interface — once one rule exists,
/// every subsequent quarantine becomes plug-and-play.
///
/// Why an alias rather than touching the L2 captive portal: the alias
/// approach works on every OPNsense regardless of whether captive
/// portal / 802.1x is configured. The downside is that the operator has
/// to wire a single firewall rule that uses the alias on first setup —
/// we surface that hint in the result if the alias was just created.
pub async fn opnsense_quarantine_mac(
    fw_url: &str,
    api_key: &str,
    api_secret: &str,
    mac: &str,
    no_tls_verify: bool,
) -> RemediationResult {
    let mac = mac.trim().to_lowercase();
    if !is_valid_mac(&mac) {
        return RemediationResult {
            action: "opnsense_quarantine_mac".into(),
            target: mac,
            success: false,
            message: "Invalid MAC format (expected aa:bb:cc:dd:ee:ff)".into(),
            reversible: false,
            undo_info: None,
        };
    }
    let client = match Client::builder()
        .danger_accept_invalid_certs(no_tls_verify)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RemediationResult {
                action: "opnsense_quarantine_mac".into(),
                target: mac,
                success: false,
                message: format!("HTTP client error: {e}"),
                reversible: true,
                undo_info: None,
            };
        }
    };
    let alias = "TC_QUARANTINE_MACS";

    // 1. Look the alias up by name. 404 / not_found → create it.
    let get_url = format!("{fw_url}/api/firewall/alias/getAliasUUID/{alias}");
    let uuid = client
        .get(&get_url)
        .basic_auth(api_key, Some(api_secret))
        .send()
        .await
        .ok()
        .and_then(|r| {
            if r.status().is_success() {
                Some(r)
            } else {
                None
            }
        });
    let mut just_created = false;
    let alias_uuid: Option<String> = match uuid {
        Some(r) => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["uuid"].as_str().map(|s| s.to_string())),
        None => None,
    };
    let alias_uuid = match alias_uuid {
        Some(u) if !u.is_empty() => u,
        _ => {
            // Create the alias.
            let add_url = format!("{fw_url}/api/firewall/alias/addItem");
            let body = serde_json::json!({
                "alias": {
                    "enabled": "1",
                    "name": alias,
                    "type": "mac",
                    "description": "ThreatClaw — quarantined MAC addresses",
                    "content": ""
                }
            });
            match client
                .post(&add_url)
                .basic_auth(api_key, Some(api_secret))
                .json(&body)
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    let v = r.json::<serde_json::Value>().await.ok();
                    just_created = true;
                    v.and_then(|v| v["uuid"].as_str().map(|s| s.to_string()))
                        .unwrap_or_default()
                }
                Ok(r) => {
                    return RemediationResult {
                        action: "opnsense_quarantine_mac".into(),
                        target: mac,
                        success: false,
                        message: format!("alias create refused: HTTP {}", r.status()),
                        reversible: true,
                        undo_info: None,
                    };
                }
                Err(e) => {
                    return RemediationResult {
                        action: "opnsense_quarantine_mac".into(),
                        target: mac,
                        success: false,
                        message: format!("alias create error: {e}"),
                        reversible: true,
                        undo_info: None,
                    };
                }
            }
        }
    };

    // 2. Read current content + append.
    let detail_url = format!("{fw_url}/api/firewall/alias/getItem/{alias_uuid}");
    let detail = match client
        .get(&detail_url)
        .basic_auth(api_key, Some(api_secret))
        .send()
        .await
    {
        Ok(r) => r.json::<serde_json::Value>().await.ok(),
        Err(_) => None,
    };
    let mut content_lines: Vec<String> = detail
        .as_ref()
        .and_then(|v| v["alias"]["content"].as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(_k, v)| {
                    v["selected"]
                        .as_i64()
                        .filter(|n| *n == 1)
                        .map(|_| _k.clone())
                })
                .collect()
        })
        .unwrap_or_default();
    if content_lines.iter().any(|m| m == &mac) {
        return RemediationResult {
            action: "opnsense_quarantine_mac".into(),
            target: mac,
            success: true,
            message: "MAC déjà en quarantaine".into(),
            reversible: true,
            undo_info: Some(format!("alias {alias} member {} (already)", "")),
        };
    }
    content_lines.push(mac.clone());
    let set_url = format!("{fw_url}/api/firewall/alias/setItem/{alias_uuid}");
    let body = serde_json::json!({
        "alias": {
            "enabled": "1",
            "name": alias,
            "type": "mac",
            "description": "ThreatClaw — quarantined MAC addresses",
            "content": content_lines.join("\n")
        }
    });
    let resp = client
        .post(&set_url)
        .basic_auth(api_key, Some(api_secret))
        .json(&body)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            // 3. Apply (reload aliases + tables).
            let _ = client
                .post(format!("{fw_url}/api/firewall/alias/reconfigure"))
                .basic_auth(api_key, Some(api_secret))
                .send()
                .await;
            tracing::warn!("REMEDIATION: Quarantined MAC {mac} via alias {alias}");
            RemediationResult {
                action: "opnsense_quarantine_mac".into(),
                target: mac.clone(),
                success: true,
                message: if just_created {
                    format!(
                        "Alias {alias} créé + MAC {mac} ajouté. \
                         Pense à attacher l'alias à une règle de blocage \
                         layer-2 sur LAN dans la GUI (Firewall → Rules → LAN)."
                    )
                } else {
                    format!("MAC {mac} ajouté à l'alias {alias}")
                },
                reversible: true,
                undo_info: Some(format!(
                    "remove member from POST {fw_url}/api/firewall/alias/setItem/{alias_uuid}"
                )),
            }
        }
        Ok(r) => RemediationResult {
            action: "opnsense_quarantine_mac".into(),
            target: mac,
            success: false,
            message: format!("alias setItem refused: HTTP {}", r.status()),
            reversible: true,
            undo_info: None,
        },
        Err(e) => RemediationResult {
            action: "opnsense_quarantine_mac".into(),
            target: mac,
            success: false,
            message: format!("alias setItem error: {e}"),
            reversible: true,
            undo_info: None,
        },
    }
}

fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

// ══════════════════════════════════════════════════════════
// Active Directory — Force password reset at next login (C26b)
// ══════════════════════════════════════════════════════════

/// Set `pwdLastSet=0` on a user object so the next login forces a
/// password change through the standard self-service portal. We
/// deliberately do NOT generate a temporary password ourselves — that
/// would mean handling secret distribution, which raises the privilege
/// requirement on the bind account. The user lands on the password
/// change screen and goes through their normal flow.
pub async fn ad_reset_password(
    host: &str,
    port: u16,
    bind_dn: &str,
    bind_pw: &str,
    base_dn: &str,
    username: &str,
    no_tls_verify: bool,
) -> RemediationResult {
    use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope};

    let url = if port == 636 {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(15))
        .set_no_tls_verify(no_tls_verify);

    let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, &url).await {
        Ok(c) => c,
        Err(e) => {
            return RemediationResult {
                action: "ad_reset_password".into(),
                target: username.into(),
                success: false,
                message: format!("LDAP connection failed: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };
    tokio::spawn(async move {
        let _ = conn.drive().await;
    });

    if let Err(e) = ldap
        .simple_bind(bind_dn, bind_pw)
        .await
        .and_then(|res| res.success().map(|_| ()))
    {
        return RemediationResult {
            action: "ad_reset_password".into(),
            target: username.into(),
            success: false,
            message: format!("LDAP bind failed: {}", e),
            reversible: true,
            undo_info: None,
        };
    }

    let filter = format!(
        "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
        username
    );
    let (results, _) = match ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["distinguishedName"])
        .await
        .and_then(|res| res.success())
    {
        Ok(r) => r,
        Err(e) => {
            return RemediationResult {
                action: "ad_reset_password".into(),
                target: username.into(),
                success: false,
                message: format!("LDAP search failed: {}", e),
                reversible: true,
                undo_info: None,
            };
        }
    };

    if results.is_empty() {
        let _ = ldap.unbind().await;
        return RemediationResult {
            action: "ad_reset_password".into(),
            target: username.into(),
            success: false,
            message: format!("Utilisateur '{}' non trouvé dans l'AD", username),
            reversible: false,
            undo_info: None,
        };
    }

    let entry = ldap3::SearchEntry::construct(results.into_iter().next().unwrap());
    let user_dn = &entry.dn;

    // pwdLastSet=0 → "must change password at next logon".
    // pwdLastSet=-1 (or some implementations: another modify with a new
    // value) would re-mark the password as "fresh" — that's the undo path.
    let mods = vec![Mod::Replace(
        "pwdLastSet",
        std::collections::HashSet::from(["0"]),
    )];

    match ldap
        .modify(user_dn, mods)
        .await
        .and_then(|res| res.success().map(|_| ()))
    {
        Ok(_) => {
            tracing::warn!(
                "REMEDIATION: Forced password reset on AD account '{}' (DN: {})",
                username,
                user_dn
            );
            let _ = ldap.unbind().await;
            RemediationResult {
                action: "ad_reset_password".into(),
                target: username.into(),
                success: true,
                message: format!(
                    "Changement de mot de passe forcé au prochain login pour '{}'",
                    username
                ),
                reversible: true,
                undo_info: Some(format!("Annuler : modify pwdLastSet=-1 sur {}", user_dn)),
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            RemediationResult {
                action: "ad_reset_password".into(),
                target: username.into(),
                success: false,
                message: format!(
                    "Echec reset password: {} — le compte de service a-t-il les droits ?",
                    e
                ),
                reversible: true,
                undo_info: None,
            }
        }
    }
}

fn is_valid_ip(ip: &str) -> bool {
    ip.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
        && !ip.is_empty()
        && ip.len() <= 45
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("10.0.0.1"));
        assert!(is_valid_ip("::1"));
        assert!(!is_valid_ip(""));
        assert!(!is_valid_ip("192.168.1.1; rm -rf /"));
        assert!(!is_valid_ip("$(whoami)"));
    }
}

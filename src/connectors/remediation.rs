//! Remediation Actions — ThreatClaw acts on the infrastructure.
//!
//! IMPORTANT: All actions require HITL approval before execution.
//! These are WRITE operations on client infrastructure.
//!
//! Supported actions:
//! - pfSense/OPNsense: block IP via firewall API
//! - Active Directory: disable compromised account via LDAP

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
        Err(e) => return RemediationResult {
            action: "pfsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: format!("HTTP client error: {}", e),
            reversible: true,
            undo_info: None,
        },
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

    let resp = match client.post(&url)
        .basic_auth(auth_user, Some(auth_secret))
        .json(&rule)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return RemediationResult {
            action: "pfsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: format!("API request failed: {}", e),
            reversible: true,
            undo_info: None,
        },
    };

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if status.is_success() {
        let rule_id = body["data"]["id"].as_i64().unwrap_or(0);
        tracing::info!("REMEDIATION: Blocked IP {} on pfSense (rule #{})", ip_to_block, rule_id);
        RemediationResult {
            action: "pfsense_block_ip".into(),
            target: ip_to_block.into(),
            success: true,
            message: format!("IP {} bloquee sur le firewall (regle #{})", ip_to_block, rule_id),
            reversible: true,
            undo_info: Some(format!("DELETE {}/api/v2/firewall/rule/{}", fw_url, rule_id)),
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
        Err(e) => return RemediationResult {
            action: "opnsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: format!("HTTP client error: {}", e),
            reversible: true,
            undo_info: None,
        },
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

    let resp = match client.post(&url)
        .basic_auth(api_key, Some(api_secret))
        .json(&rule)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return RemediationResult {
            action: "opnsense_block_ip".into(),
            target: ip_to_block.into(),
            success: false,
            message: format!("OPNsense API error: {}", e),
            reversible: true,
            undo_info: None,
        },
    };

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if status.is_success() {
        let uuid = body["uuid"].as_str().unwrap_or("");

        // Apply the rule
        let apply_url = format!("{}/api/firewall/filter/apply", fw_url);
        let _ = client.post(&apply_url)
            .basic_auth(api_key, Some(api_secret))
            .send()
            .await;

        tracing::info!("REMEDIATION: Blocked IP {} on OPNsense (uuid: {})", ip_to_block, uuid);
        RemediationResult {
            action: "opnsense_block_ip".into(),
            target: ip_to_block.into(),
            success: true,
            message: format!("IP {} bloquee sur OPNsense", ip_to_block),
            reversible: true,
            undo_info: Some(format!("DELETE {}/api/firewall/filter/delRule/{}", fw_url, uuid)),
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
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, Mod};

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
        Err(e) => return RemediationResult {
            action: "ad_disable_account".into(),
            target: username_to_disable.into(),
            success: false,
            message: format!("LDAP connection failed: {}", e),
            reversible: true,
            undo_info: None,
        },
    };

    tokio::spawn(async move { let _ = conn.drive().await; });

    if let Err(e) = ldap.simple_bind(bind_dn, bind_pw).await
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
    let filter = format!("(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))", username_to_disable);
    let (results, _) = match ldap.search(base_dn, Scope::Subtree, &filter, vec!["distinguishedName", "userAccountControl"])
        .await
        .and_then(|res| res.success())
    {
        Ok(r) => r,
        Err(e) => return RemediationResult {
            action: "ad_disable_account".into(),
            target: username_to_disable.into(),
            success: false,
            message: format!("LDAP search failed: {}", e),
            reversible: true,
            undo_info: None,
        },
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
    let current_uac = entry.attrs.get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(512); // 512 = NORMAL_ACCOUNT

    // Set ACCOUNTDISABLE flag (0x0002)
    let new_uac = current_uac | 0x0002;

    let new_uac_str = new_uac.to_string();
    let mods = vec![
        Mod::Replace("userAccountControl", std::collections::HashSet::from([new_uac_str.as_str()])),
    ];

    match ldap.modify(user_dn, mods).await.and_then(|res| res.success().map(|_| ())) {
        Ok(_) => {
            tracing::warn!("REMEDIATION: Disabled AD account '{}' (DN: {})", username_to_disable, user_dn);
            let _ = ldap.unbind().await;
            RemediationResult {
                action: "ad_disable_account".into(),
                target: username_to_disable.into(),
                success: true,
                message: format!("Compte '{}' desactive dans Active Directory", username_to_disable),
                reversible: true,
                undo_info: Some(format!("Re-enable: set userAccountControl={} on {}", current_uac, user_dn)),
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            RemediationResult {
                action: "ad_disable_account".into(),
                target: username_to_disable.into(),
                success: false,
                message: format!("Echec desactivation: {} — le compte de service a-t-il les droits ?", e),
                reversible: true,
                undo_info: None,
            }
        }
    }
}

fn is_valid_ip(ip: &str) -> bool {
    ip.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':')
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

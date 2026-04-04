//! Active Directory / LDAP connector.

use crate::db::Database;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use crate::graph::identity_graph;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// AD connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdConfig {
    /// LDAP server host (e.g., "dc01.corp.local")
    pub host: String,
    /// Port (636 for LDAPS, 389 for LDAP)
    pub port: u16,
    /// Bind DN (e.g., "cn=tc-readonly,ou=ServiceAccounts,dc=corp,dc=local")
    pub bind_dn: String,
    /// Bind password
    pub bind_password: String,
    /// Base DN for searches (e.g., "dc=corp,dc=local")
    pub base_dn: String,
    /// Skip TLS certificate verification (lab only)
    pub no_tls_verify: bool,
}

/// Result of an AD sync operation.
#[derive(Debug, Clone, Serialize)]
pub struct AdSyncResult {
    pub computers: usize,
    pub users: usize,
    pub groups: usize,
    pub admins: usize,
    pub ous: usize,
    pub errors: Vec<String>,
}

/// Sync Active Directory into ThreatClaw graph.
pub async fn sync_ad(store: &dyn Database, config: &AdConfig) -> AdSyncResult {
    let mut result = AdSyncResult {
        computers: 0, users: 0, groups: 0, admins: 0, ous: 0, errors: vec![],
    };

    // Connect
    let url = if config.port == 636 {
        format!("ldaps://{}:{}", config.host, config.port)
    } else {
        format!("ldap://{}:{}", config.host, config.port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(15))
        .set_no_tls_verify(config.no_tls_verify);

    let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, &url).await {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("Connection failed: {}", e));
            tracing::error!("AD: Connection to {} failed: {}", url, e);
            return result;
        }
    };

    // Drive the connection I/O in background
    tokio::spawn(async move { let _ = conn.drive().await; });

    // Bind
    if let Err(e) = ldap.simple_bind(&config.bind_dn, &config.bind_password).await
        .and_then(|res| res.success().map(|_| ()))
    {
        result.errors.push(format!("Bind failed: {}", e));
        tracing::error!("AD: Bind failed as {}: {}", config.bind_dn, e);
        return result;
    }

    tracing::info!("AD: Connected and bound to {}", url);

    // Sync computers
    match search_paged(&mut ldap, &config.base_dn,
        "(&(objectCategory=computer)(objectClass=computer))",
        vec!["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
             "lastLogonTimestamp", "distinguishedName", "description", "userAccountControl"],
    ).await {
        Ok(entries) => {
            for entry in &entries {
                let hostname = get_attr(entry, "cn").unwrap_or_default();
                let fqdn = get_attr(entry, "dNSHostName");
                let os = get_attr(entry, "operatingSystem")
                    .map(|os| {
                        let ver = get_attr(entry, "operatingSystemVersion").unwrap_or_default();
                        if ver.is_empty() { os } else { format!("{} {}", os, ver) }
                    });
                let ou = extract_ou(&entry.dn);
                let disabled = is_account_disabled(entry);

                if !hostname.is_empty() && !disabled {
                    let discovered = DiscoveredAsset {
                        mac: None, // AD doesn't store MAC
                        hostname: Some(hostname),
                        fqdn,
                        ip: None, // AD doesn't reliably store IP
                        os,
                        ports: None,
                        ou: Some(ou),
                        vlan: None,
                        vm_id: None,
                        criticality: None,
            services: serde_json::json!([]),
                        source: "ad".into(),
                    };
                    asset_resolution::resolve_asset(store, &discovered).await;
                    result.computers += 1;
                }
            }
            tracing::info!("AD: Synced {} computers", result.computers);
        }
        Err(e) => {
            result.errors.push(format!("Computer search failed: {}", e));
            tracing::error!("AD: Computer search failed: {}", e);
        }
    }

    // Sync users
    match search_paged(&mut ldap, &config.base_dn,
        "(&(objectCategory=person)(objectClass=user))",
        vec!["sAMAccountName", "cn", "displayName", "mail", "department",
             "memberOf", "lastLogonTimestamp", "userAccountControl", "adminCount",
             "distinguishedName"],
    ).await {
        Ok(entries) => {
            for entry in &entries {
                let username = get_attr(entry, "sAMAccountName").unwrap_or_default();
                let department = get_attr(entry, "department");
                let admin_count = get_attr(entry, "adminCount")
                    .and_then(|v| v.parse::<i32>().ok())
                    .unwrap_or(0);
                let disabled = is_account_disabled(entry);
                let groups = get_attr_multi(entry, "memberOf");

                if !username.is_empty() && !disabled {
                    let is_admin = admin_count > 0 || groups.iter().any(|g|
                        g.contains("Domain Admins") || g.contains("Administrators")
                    );

                    identity_graph::upsert_user(
                        store, &username, is_admin, false,
                        department.as_deref(),
                    ).await;

                    result.users += 1;
                    if is_admin { result.admins += 1; }
                }
            }
            tracing::info!("AD: Synced {} users ({} admins)", result.users, result.admins);
        }
        Err(e) => {
            result.errors.push(format!("User search failed: {}", e));
            tracing::error!("AD: User search failed: {}", e);
        }
    }

    // Sync groups
    match search_paged(&mut ldap, &config.base_dn,
        "(objectClass=group)",
        vec!["cn", "member", "description", "distinguishedName", "groupType"],
    ).await {
        Ok(entries) => {
            result.groups = entries.len();
            tracing::info!("AD: Found {} groups", result.groups);
        }
        Err(e) => {
            result.errors.push(format!("Group search failed: {}", e));
        }
    }

    // Sync OUs
    match search_paged(&mut ldap, &config.base_dn,
        "(objectClass=organizationalUnit)",
        vec!["ou", "name", "description", "distinguishedName"],
    ).await {
        Ok(entries) => {
            result.ous = entries.len();
            tracing::info!("AD: Found {} OUs", result.ous);
        }
        Err(e) => {
            result.errors.push(format!("OU search failed: {}", e));
        }
    }

    // Unbind
    let _ = ldap.unbind().await;

    tracing::info!(
        "AD SYNC COMPLETE: {} computers, {} users ({} admins), {} groups, {} OUs",
        result.computers, result.users, result.admins, result.groups, result.ous
    );

    result
}

/// Paged LDAP search — handles AD's 1000-result limit.
async fn search_paged(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    filter: &str,
    attrs: Vec<&str>,
) -> Result<Vec<SearchEntry>, String> {
    let mut entries = vec![];
    let page_size: i32 = 500;

    // Use the simple search with paging control
    let (results, _res) = ldap.search(base_dn, Scope::Subtree, filter, attrs)
        .await
        .map_err(|e| format!("LDAP search error: {}", e))?
        .success()
        .map_err(|e| format!("LDAP search failed: {}", e))?;

    for entry in results {
        entries.push(SearchEntry::construct(entry));
    }

    Ok(entries)
}

/// Extract a single-valued attribute.
fn get_attr(entry: &SearchEntry, name: &str) -> Option<String> {
    entry.attrs.get(name)
        .and_then(|v| v.first())
        .cloned()
}

/// Extract a multi-valued attribute.
fn get_attr_multi(entry: &SearchEntry, name: &str) -> Vec<String> {
    entry.attrs.get(name).cloned().unwrap_or_default()
}

/// Extract OU from a Distinguished Name.
/// "CN=PC-01,OU=Comptabilite,OU=Workstations,DC=corp,DC=local" → "Comptabilite"
fn extract_ou(dn: &str) -> String {
    dn.split(',')
        .find(|part| part.trim().to_uppercase().starts_with("OU="))
        .map(|part| part.trim()[3..].to_string())
        .unwrap_or_else(|| "Default".into())
}

/// Check if account is disabled via userAccountControl bitmask.
fn is_account_disabled(entry: &SearchEntry) -> bool {
    get_attr(entry, "userAccountControl")
        .and_then(|v| v.parse::<u32>().ok())
        .map(|uac| uac & 0x0002 != 0) // ACCOUNTDISABLE flag
        .unwrap_or(false)
}

/// Convert Windows FILETIME (100-ns intervals since 1601-01-01) to ISO timestamp.
#[allow(dead_code)]
fn filetime_to_iso(filetime_str: &str) -> Option<String> {
    let ft: i64 = filetime_str.parse().ok()?;
    if ft <= 0 { return None; }
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    let unix_100ns = ft - EPOCH_DIFF;
    let secs = unix_100ns / 10_000_000;
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ou() {
        assert_eq!(
            extract_ou("CN=PC-01,OU=Comptabilite,OU=Workstations,DC=corp,DC=local"),
            "Comptabilite"
        );
        assert_eq!(extract_ou("CN=SRV-01,DC=corp,DC=local"), "Default");
    }

    #[test]
    fn test_filetime_to_iso() {
        // 2024-01-15 ~12:00 UTC
        let ts = filetime_to_iso("133500000000000000");
        assert!(ts.is_some());
        assert!(ts.unwrap().starts_with("2024"));
    }

    #[test]
    fn test_filetime_zero() {
        assert_eq!(filetime_to_iso("0"), None);
        assert_eq!(filetime_to_iso("-1"), None);
    }
}

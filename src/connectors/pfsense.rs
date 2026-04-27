//! pfSense / OPNsense Connector — real REST API integration.
//!
//! Discovers network topology: ARP table, DHCP leases, firewall rules,
//! interfaces, and VLANs. Feeds assets into the graph via Asset Resolution.
//!
//! Supports both:
//! - pfSense (requires pfSense-pkg-RESTAPI v2 package)
//! - OPNsense (built-in API)
//!
//! Auth: Basic auth (pfSense) or API Key/Secret (OPNsense)

use crate::db::Database;
use crate::db::threatclaw_store::NewFirewallEvent;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Firewall connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Firewall URL (e.g., "https://192.168.1.1")
    pub url: String,
    /// Firewall type
    pub fw_type: FirewallType,
    /// Auth: username (pfSense) or API key (OPNsense)
    pub auth_user: String,
    /// Auth: password (pfSense) or API secret (OPNsense)
    pub auth_secret: String,
    /// Skip TLS certificate verification (self-signed certs)
    pub no_tls_verify: bool,
    // ── C27: per-scope log cursors (ISO of the highest timestamp we've
    //   already ingested). `None` on first sync → 1 h backfill window.
    //   These map 1:1 to /var/log/<scope>/ on the OPNsense host.
    #[serde(default)]
    pub cursor_log_audit: Option<String>,
    #[serde(default)]
    pub cursor_log_system: Option<String>,
    #[serde(default)]
    pub cursor_log_filter: Option<String>,
    #[serde(default)]
    pub cursor_log_suricata: Option<String>,
    #[serde(default)]
    pub cursor_log_configd: Option<String>,
    #[serde(default)]
    pub cursor_log_dnsmasq: Option<String>,
    #[serde(default)]
    pub cursor_log_wireguard: Option<String>,
    #[serde(default)]
    pub cursor_log_resolver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallType {
    PfSense,
    OPNsense,
}

/// Result of a firewall sync operation.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FirewallSyncResult {
    // ── Inventory (existing) ──
    pub arp_entries: usize,
    pub dhcp_leases: usize,
    pub interfaces: usize,
    pub vlans: usize,
    pub firewall_rules: usize,
    pub assets_resolved: usize,
    // ── Telemetry (C13: full SIEM-style ingestion) ──
    /// pf log entries inserted into firewall_events this cycle.
    pub firewall_log_ingested: usize,
    /// pf log entries deleted by 24 h retention this cycle.
    pub firewall_log_pruned: i64,
    /// Active connections snapshot (pf_states table size).
    pub pf_states_active: i64,
    /// Active OpenVPN sessions, OpenVPN LOGGED_IN edges pushed.
    pub openvpn_sessions: usize,
    /// WireGuard peers seen + how many had a recent handshake.
    pub wireguard_peers_total: usize,
    pub wireguard_peers_active: usize,
    /// IPsec phase 1 sessions active.
    pub ipsec_phase1_active: usize,
    /// Audit log entries (UI logins / config changes).
    pub audit_events: usize,
    /// Gateway status.
    pub gateways_total: usize,
    pub gateways_offline: usize,
    /// Aliases (firewall lists used in rules).
    pub aliases_count: usize,
    /// Self-reported version of the firewall (last segment of /system/system_information).
    pub system_version: Option<String>,
    // ── C27: per-scope log ingestion counts + advanced cursors.
    //   Each scope is read incrementally from /api/diagnostics/log/core/<scope>
    //   and its rows are inserted into `logs` tagged `opnsense.<scope>` so
    //   the Sigma engine (logsource_category='opnsense') picks them up.
    pub audit_logs_ingested: usize,
    pub system_logs_ingested: usize,
    pub filter_logs_ingested: usize,
    pub suricata_alerts_ingested: usize,
    pub configd_logs_ingested: usize,
    pub dnsmasq_logs_ingested: usize,
    pub wireguard_logs_ingested: usize,
    pub resolver_logs_ingested: usize,
    pub cursor_log_audit: Option<String>,
    pub cursor_log_system: Option<String>,
    pub cursor_log_filter: Option<String>,
    pub cursor_log_suricata: Option<String>,
    pub cursor_log_configd: Option<String>,
    pub cursor_log_dnsmasq: Option<String>,
    pub cursor_log_wireguard: Option<String>,
    pub cursor_log_resolver: Option<String>,
    pub errors: Vec<String>,
}

/// ARP entry from the firewall.
#[derive(Debug, Clone, Deserialize)]
struct ArpEntry {
    ip: Option<String>,
    mac: Option<String>,
    hostname: Option<String>,
    #[serde(alias = "interface", alias = "intf")]
    interface: Option<String>,
    #[serde(alias = "intf_description")]
    interface_desc: Option<String>,
}

/// DHCP lease from the firewall.
#[derive(Debug, Clone, Deserialize)]
struct DhcpLease {
    #[serde(alias = "address")]
    ip: Option<String>,
    #[serde(alias = "hwaddr")]
    mac: Option<String>,
    hostname: Option<String>,
    #[serde(alias = "if")]
    interface: Option<String>,
    #[serde(alias = "if_descr")]
    interface_desc: Option<String>,
    #[serde(alias = "active_status", alias = "state")]
    status: Option<String>,
}

/// Sync firewall data into ThreatClaw graph.
pub async fn sync_firewall(store: &dyn Database, config: &FirewallConfig) -> FirewallSyncResult {
    let mut result = FirewallSyncResult::default();

    let client = match build_client(config) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client error: {}", e));
            return result;
        }
    };

    tracing::info!(
        "FIREWALL: Connecting to {} ({:?})",
        config.url,
        config.fw_type
    );

    // 1. Sync ARP table (all devices on network)
    match fetch_arp(&client, config).await {
        Ok(entries) => {
            result.arp_entries = entries.len();
            for entry in &entries {
                if let (Some(ip), Some(mac)) = (&entry.ip, &entry.mac) {
                    if !ip.is_empty() && !mac.is_empty() && mac != "(incomplete)" {
                        let vlan = extract_vlan_from_interface(entry.interface.as_deref());
                        let discovered = DiscoveredAsset {
                            mac: Some(mac.clone()),
                            hostname: entry.hostname.clone().filter(|h| !h.is_empty() && h != "?"),
                            fqdn: None,
                            ip: Some(ip.clone()),
                            os: None,
                            ports: None,
                            ou: None,
                            vlan,
                            vm_id: None,
                            criticality: None,
                            services: serde_json::json!([]),
                            source: config.fw_type.source_name().into(),
                        };
                        asset_resolution::resolve_asset(store, &discovered).await;
                        result.assets_resolved += 1;
                    }
                }
            }
            tracing::info!(
                "FIREWALL: {} ARP entries → {} assets resolved",
                result.arp_entries,
                result.assets_resolved
            );
        }
        Err(e) => {
            result.errors.push(format!("ARP fetch failed: {}", e));
            tracing::error!("FIREWALL: ARP fetch failed: {}", e);
        }
    }

    // 2. Sync DHCP leases (enrich with hostname)
    match fetch_dhcp_leases(&client, config).await {
        Ok(leases) => {
            result.dhcp_leases = leases.len();
            for lease in &leases {
                if let (Some(ip), Some(mac)) = (&lease.ip, &lease.mac) {
                    if !ip.is_empty() && !mac.is_empty() {
                        let vlan = extract_vlan_from_interface(lease.interface.as_deref());
                        let discovered = DiscoveredAsset {
                            mac: Some(mac.clone()),
                            hostname: lease.hostname.clone().filter(|h| !h.is_empty()),
                            fqdn: None,
                            ip: Some(ip.clone()),
                            os: None,
                            ports: None,
                            ou: None,
                            vlan,
                            vm_id: None,
                            criticality: None,
                            services: serde_json::json!([]),
                            source: "dhcp".into(),
                        };
                        asset_resolution::resolve_asset(store, &discovered).await;
                        result.assets_resolved += 1;
                    }
                }
            }
            tracing::info!("FIREWALL: {} DHCP leases synced", result.dhcp_leases);
        }
        Err(e) => {
            result.errors.push(format!("DHCP fetch failed: {}", e));
            tracing::error!("FIREWALL: DHCP fetch failed: {}", e);
        }
    }

    // 3. Count interfaces and VLANs (for topology awareness)
    match fetch_interfaces(&client, config).await {
        Ok(count) => {
            result.interfaces = count;
        }
        Err(e) => {
            result.errors.push(format!("Interfaces fetch: {}", e));
        }
    }

    match fetch_vlans(&client, config).await {
        Ok(count) => {
            result.vlans = count;
        }
        Err(e) => {
            result.errors.push(format!("VLANs fetch: {}", e));
        }
    }

    match fetch_firewall_rules(&client, config).await {
        Ok(count) => {
            result.firewall_rules = count;
        }
        Err(e) => {
            result.errors.push(format!("Rules fetch: {}", e));
        }
    }

    // ── Telemetry / SIEM-style ingestion (C13) ──
    // OPNsense only for now; pfSense's REST API package exposes a
    // similar but not identical surface — we'll wire pfSense paths
    // when we have a real pfSense to verify against.
    if config.fw_type == FirewallType::OPNsense {
        // 4. Firewall log → firewall_events table (rolling 24 h).
        match fetch_firewall_log(&client, config).await {
            Ok(events) => {
                let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
                if !events.is_empty() {
                    match store.insert_firewall_events(&events).await {
                        Ok(n) => result.firewall_log_ingested = n,
                        Err(e) => {
                            result.errors.push(format!("Firewall log insert: {}", e));
                        }
                    }
                    // Mirror BLOCK events into the logs table so the Sigma
                    // engine can run pattern rules against single events
                    // (backdoor port hit, RFC1918 spoof, etc.). Volumetric
                    // detection stays on firewall_events via SQL aggregates
                    // — this is the complementary single-line path.
                    let mut sigma_logs = 0usize;
                    for ev in &events {
                        if ev.action != "block" {
                            continue;
                        }
                        let entry = serde_json::json!({
                            "fw_source": ev.fw_source,
                            "interface": ev.interface,
                            "action": ev.action,
                            "direction": ev.direction,
                            "proto": ev.proto,
                            "src_ip": ev.src_ip,
                            "src_port": ev.src_port,
                            "dst_ip": ev.dst_ip,
                            "dst_port": ev.dst_port,
                            "rule_id": ev.rule_id,
                        });
                        let host = ev.src_ip.as_deref().unwrap_or("-");
                        let ts = ev.timestamp.to_rfc3339();
                        if store
                            .insert_log("opnsense.firewall", host, &entry, &ts)
                            .await
                            .is_ok()
                        {
                            sigma_logs += 1;
                        }
                    }
                    if sigma_logs > 0 {
                        tracing::debug!(
                            "OPNSENSE: mirrored {} block events into logs for Sigma",
                            sigma_logs
                        );
                    }
                }
                // Always prune; cheap if nothing's old.
                if let Ok(n) = store.prune_firewall_events(cutoff).await {
                    result.firewall_log_pruned = n;
                }
            }
            Err(e) => result.errors.push(format!("Firewall log fetch: {}", e)),
        }

        // 5. PF states (active connections snapshot).
        match fetch_pf_states_count(&client, config).await {
            Ok(n) => result.pf_states_active = n,
            Err(e) => result.errors.push(format!("PF states: {}", e)),
        }

        // 6. OpenVPN sessions → identity_graph LOGGED_IN edges.
        match fetch_openvpn_sessions(&client, config).await {
            Ok(sessions) => {
                for s in &sessions {
                    if let (Some(u), Some(ip)) = (&s.common_name, &s.real_address) {
                        let real_ip = ip.split(':').next().unwrap_or(ip);
                        crate::graph::identity_graph::record_login(
                            store, u, "vpn", real_ip, "openvpn", true,
                        )
                        .await;
                    }
                }
                result.openvpn_sessions = sessions.len();
            }
            Err(e) => result.errors.push(format!("OpenVPN: {}", e)),
        }

        // 7. WireGuard peers + active handshakes.
        match fetch_wireguard_peers(&client, config).await {
            Ok((total, active)) => {
                result.wireguard_peers_total = total;
                result.wireguard_peers_active = active;
            }
            Err(e) => result.errors.push(format!("WireGuard: {}", e)),
        }

        // 8. IPsec phase 1.
        match fetch_ipsec_phase1(&client, config).await {
            Ok(n) => result.ipsec_phase1_active = n,
            Err(e) => result.errors.push(format!("IPsec: {}", e)),
        }

        // 9. C27 — pull 8 /var/log/<scope>/ files via the JSON API. Each
        //    row goes into `logs` tagged `opnsense.<scope>` so the Sigma
        //    engine (logsource_category='opnsense') matches them. This is
        //    the path that lets a SOC ingest OPNsense without the operator
        //    having to configure syslog forwarding.
        let host = config
            .url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("opnsense")
            .to_string();
        for (scope, cur_in, cnt_out, cur_out) in [
            (
                "audit",
                config.cursor_log_audit.as_deref(),
                &mut result.audit_logs_ingested,
                &mut result.cursor_log_audit,
            ),
            (
                "system",
                config.cursor_log_system.as_deref(),
                &mut result.system_logs_ingested,
                &mut result.cursor_log_system,
            ),
            (
                "filter",
                config.cursor_log_filter.as_deref(),
                &mut result.filter_logs_ingested,
                &mut result.cursor_log_filter,
            ),
            (
                "suricata",
                config.cursor_log_suricata.as_deref(),
                &mut result.suricata_alerts_ingested,
                &mut result.cursor_log_suricata,
            ),
            (
                "configd",
                config.cursor_log_configd.as_deref(),
                &mut result.configd_logs_ingested,
                &mut result.cursor_log_configd,
            ),
            (
                "dnsmasq",
                config.cursor_log_dnsmasq.as_deref(),
                &mut result.dnsmasq_logs_ingested,
                &mut result.cursor_log_dnsmasq,
            ),
            (
                "wireguard",
                config.cursor_log_wireguard.as_deref(),
                &mut result.wireguard_logs_ingested,
                &mut result.cursor_log_wireguard,
            ),
            (
                "resolver",
                config.cursor_log_resolver.as_deref(),
                &mut result.resolver_logs_ingested,
                &mut result.cursor_log_resolver,
            ),
        ] {
            match ingest_log_scope(store, &client, config, &host, scope, cur_in).await {
                Ok((n, new_cur)) => {
                    *cnt_out = n;
                    if new_cur.is_some() {
                        *cur_out = new_cur;
                    }
                }
                Err(e) => result.errors.push(format!("log/{}: {}", scope, e)),
            }
        }
        // Legacy field — kept so existing dashboard widgets don't break.
        result.audit_events = result.audit_logs_ingested;

        // 10. Gateway status (uptime, loss).
        match fetch_gateways(&client, config).await {
            Ok((total, offline)) => {
                result.gateways_total = total;
                result.gateways_offline = offline;
            }
            Err(e) => result.errors.push(format!("Gateways: {}", e)),
        }

        // 11. Aliases (firewall lists).
        match fetch_aliases_count(&client, config).await {
            Ok(n) => result.aliases_count = n,
            Err(e) => result.errors.push(format!("Aliases: {}", e)),
        }

        // 12. System info (version banner).
        match fetch_system_info(&client, config).await {
            Ok(v) => result.system_version = v,
            Err(e) => result.errors.push(format!("System info: {}", e)),
        }

        // 13. Baseline monitoring — compare current counts against
        //     the previous sync. ±25 % delta on firewall_rules or
        //     aliases_count is a defense-evasion / accidental wipe
        //     signal worth surfacing as a HIGH finding.
        check_baseline_drift(
            store,
            "opnsense",
            result.firewall_rules,
            result.aliases_count,
        )
        .await;
    }

    tracing::info!(
        "FIREWALL SYNC COMPLETE: {} ARP, {} DHCP, {} ifaces, {} rules, {} assets, \
         fw_log+{}/-{}, pf_states={}, vpn={}, wg={}/{}, ipsec={}, gw={}/{}, \
         logs[audit={} sys={} filt={} suri={} cfgd={} dns={} wg={} res={}]",
        result.arp_entries,
        result.dhcp_leases,
        result.interfaces,
        result.firewall_rules,
        result.assets_resolved,
        result.firewall_log_ingested,
        result.firewall_log_pruned,
        result.pf_states_active,
        result.openvpn_sessions,
        result.wireguard_peers_active,
        result.wireguard_peers_total,
        result.ipsec_phase1_active,
        result.gateways_total - result.gateways_offline,
        result.gateways_total,
        result.audit_logs_ingested,
        result.system_logs_ingested,
        result.filter_logs_ingested,
        result.suricata_alerts_ingested,
        result.configd_logs_ingested,
        result.dnsmasq_logs_ingested,
        result.wireguard_logs_ingested,
        result.resolver_logs_ingested,
    );

    result
}

impl FirewallType {
    fn source_name(&self) -> &str {
        match self {
            FirewallType::PfSense => "pfSense",
            FirewallType::OPNsense => "opnsense",
        }
    }
}

/// Compare current rule + alias counts against the previously-seen
/// baseline. ±25 % delta in either direction is logged as a HIGH
/// finding — large enough to not fire on routine ops, small enough to
/// catch defense-evasion (mass rule disable / alias wipe).
///
/// Baseline is stored under `_baseline` / `firewall_<src>` as a JSON
/// `{firewall_rules, aliases_count, ts}`. First run: just stores the
/// baseline, no finding.
async fn check_baseline_drift(store: &dyn Database, fw_source: &str, rules: usize, aliases: usize) {
    let key = format!("firewall_{}", fw_source);
    let prev = store.get_setting("_baseline", &key).await.ok().flatten();
    let now = chrono::Utc::now().to_rfc3339();
    let snapshot = serde_json::json!({
        "firewall_rules": rules,
        "aliases_count": aliases,
        "ts": now,
    });

    if let Some(prev) = prev {
        let prev_rules = prev
            .get("firewall_rules")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let prev_aliases = prev
            .get("aliases_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        for (label, current, prev_n) in [
            ("firewall_rules", rules, prev_rules),
            ("aliases_count", aliases, prev_aliases),
        ] {
            if prev_n == 0 {
                continue;
            }
            let delta = (current as i64 - prev_n as i64).abs() as f64 / prev_n as f64;
            if delta >= 0.25 {
                let direction = if current > prev_n {
                    "increased"
                } else {
                    "decreased"
                };
                let _ = store
                    .insert_finding(&crate::db::threatclaw_store::NewFinding {
                        skill_id: format!("skill-{fw_source}"),
                        title: format!("{fw_source} {label} {direction} by {:.0}%", delta * 100.0),
                        description: Some(format!(
                            "{label} went from {prev_n} to {current} between syncs ({direction}). \
                             Sudden large changes can indicate defense-evasion, \
                             accidental wipe, or compromise of the firewall admin."
                        )),
                        severity: "high".into(),
                        category: Some("firewall_drift".into()),
                        asset: Some(fw_source.into()),
                        source: Some(format!("skill-{fw_source}")),
                        metadata: Some(serde_json::json!({
                            "prev": prev_n,
                            "current": current,
                            "delta_pct": (delta * 100.0).round(),
                            "direction": direction,
                            "metric": label,
                        })),
                    })
                    .await;
                tracing::warn!(
                    "BASELINE DRIFT: {fw_source} {label} {prev_n} → {current} ({direction})"
                );
            }
        }
    }

    let _ = store.set_setting("_baseline", &key, &snapshot).await;
}

fn build_client(config: &FirewallConfig) -> Result<Client, String> {
    Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

/// Fetch ARP table from firewall.
async fn fetch_arp(client: &Client, config: &FirewallConfig) -> Result<Vec<ArpEntry>, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/diagnostics/arp_table", config.url),
        FirewallType::OPNsense => format!("{}/api/diagnostics/interface/getArp", config.url),
    };

    let resp = client
        .get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("ARP request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("ARP: HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("ARP parse error: {}", e))?;

    // pfSense wraps in {data: [...]}, OPNsense returns array directly
    let entries_val = if config.fw_type == FirewallType::PfSense {
        body.get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]))
    } else {
        body
    };

    let entries: Vec<ArpEntry> =
        serde_json::from_value(entries_val).map_err(|e| format!("ARP deserialize error: {}", e))?;

    Ok(entries)
}

/// Fetch DHCP leases from firewall.
///
/// OPNsense ships several DHCP backends — historically ISC dhcpd, but
/// 26+ defaults to Kea or Dnsmasq. We probe each known endpoint in
/// turn and merge whatever responds. A 404 on a backend just means
/// "not enabled here", not a hard failure.
async fn fetch_dhcp_leases(
    client: &Client,
    config: &FirewallConfig,
) -> Result<Vec<DhcpLease>, String> {
    if config.fw_type == FirewallType::PfSense {
        // pfSense API v2 ships a single endpoint (data: [...]). No
        // per-backend probing needed.
        let url = format!("{}/api/v2/services/dhcpd/lease", config.url);
        let resp = client
            .get(&url)
            .basic_auth(&config.auth_user, Some(&config.auth_secret))
            .send()
            .await
            .map_err(|e| format!("DHCP request failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("DHCP: HTTP {}", resp.status()));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("DHCP parse error: {}", e))?;
        let leases_val = body
            .get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let leases: Vec<DhcpLease> = serde_json::from_value(leases_val)
            .map_err(|e| format!("DHCP deserialize error: {}", e))?;
        return Ok(leases);
    }

    // OPNsense — try each backend, merge whatever returns.
    let endpoints = [
        (
            "dnsmasq",
            format!("{}/api/dnsmasq/leases/search", config.url),
        ),
        ("kea", format!("{}/api/kea/leases4/search", config.url)),
        (
            "isc-dhcpd",
            format!("{}/api/dhcpv4/leases/searchLease", config.url),
        ),
    ];

    let mut merged: Vec<DhcpLease> = Vec::new();
    let mut tried_any_ok = false;
    let mut last_err: Option<String> = None;

    for (label, url) in &endpoints {
        let resp = match client
            .get(url)
            .basic_auth(&config.auth_user, Some(&config.auth_secret))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(format!("{} request error: {}", label, e));
                continue;
            }
        };
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            // Backend not enabled — perfectly normal.
            continue;
        }
        if !status.is_success() {
            last_err = Some(format!("{}: HTTP {}", label, status));
            continue;
        }
        let body: serde_json::Value = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                last_err = Some(format!("{} parse error: {}", label, e));
                continue;
            }
        };
        let rows = body
            .get("rows")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        match serde_json::from_value::<Vec<DhcpLease>>(rows) {
            Ok(leases) => {
                tried_any_ok = true;
                tracing::info!("DHCP {}: {} leases", label, leases.len());
                merged.extend(leases);
            }
            Err(e) => {
                last_err = Some(format!("{} deserialize error: {}", label, e));
            }
        }
    }

    if !tried_any_ok {
        // Every backend failed. If the last error is just "endpoint not
        // found", treat it as zero leases (OPNsense without any DHCP
        // enabled) rather than a hard error that the operator has to
        // care about.
        if let Some(e) = last_err {
            if e.contains("404") {
                return Ok(vec![]);
            }
            return Err(e);
        }
        return Ok(vec![]);
    }
    Ok(merged)
}

/// Fetch interface count.
async fn fetch_interfaces(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/interface", config.url),
        FirewallType::OPNsense => format!("{}/api/interfaces/overview/export", config.url),
    };

    let resp = client
        .get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("Interfaces request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Interfaces: HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Interfaces parse: {}", e))?;

    let count = if config.fw_type == FirewallType::PfSense {
        body.get("data")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    } else {
        body.as_array().map(|a| a.len()).unwrap_or(0)
    };

    tracing::info!("FIREWALL: {} interfaces found", count);
    Ok(count)
}

/// Fetch VLAN count.
async fn fetch_vlans(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/interface/vlan", config.url),
        FirewallType::OPNsense => format!("{}/api/interfaces/vlan_settings/searchItem", config.url),
    };

    let resp = client
        .get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("VLANs request: {}", e))?;

    if !resp.status().is_success() {
        return Ok(0);
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("VLANs parse: {}", e))?;

    let count = if config.fw_type == FirewallType::PfSense {
        body.get("data")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    } else {
        body.get("rows")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    };

    tracing::info!("FIREWALL: {} VLANs found", count);
    Ok(count)
}

/// Fetch firewall rule count.
async fn fetch_firewall_rules(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/firewall/rule", config.url),
        FirewallType::OPNsense => format!("{}/api/firewall/filter/searchRule", config.url),
    };

    let resp = client
        .get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("Rules request: {}", e))?;

    if !resp.status().is_success() {
        return Ok(0);
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Rules parse: {}", e))?;

    let count = if config.fw_type == FirewallType::PfSense {
        body.get("data")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    } else {
        body.get("rows")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    };

    tracing::info!("FIREWALL: {} firewall rules found", count);
    Ok(count)
}

/// Extract VLAN ID from interface name (e.g., "em1.10" → 10, "vtnet1_vlan20" → 20).
fn extract_vlan_from_interface(interface: Option<&str>) -> Option<u16> {
    let iface = interface?;

    // pfSense format: "em1.10"
    if let Some(pos) = iface.rfind('.') {
        if let Ok(vlan) = iface[pos + 1..].parse::<u16>() {
            return Some(vlan);
        }
    }

    // OPNsense format: "vtnet1_vlan10"
    if let Some(pos) = iface.find("vlan") {
        if let Ok(vlan) = iface[pos + 4..].parse::<u16>() {
            return Some(vlan);
        }
    }

    None
}

// ═══════════════════════════════════════════════════════════════════
// C13 — SIEM-style telemetry fetchers (OPNsense)
// Each function consumes one OPNsense API endpoint and converts the
// response into the shape the rest of the codebase expects (DB rows,
// identity_graph edges, or scalar counters).
// ═══════════════════════════════════════════════════════════════════

/// Helper: GET an OPNsense endpoint with basic auth + timeout, return
/// JSON or a clean error string.
async fn opn_get_json(
    client: &Client,
    config: &FirewallConfig,
    path: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", config.url, path);
    let resp = client
        .get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("HTTP request error: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON parse error: {}", e))
}

/// Pull recent pf log entries. The endpoint returns the last `limit`
/// matches (default 100) of pf rules in chronological order. We parse
/// the `__timestamp__`, `action`, `src`/`dst`, etc., into the DB shape.
async fn fetch_firewall_log(
    client: &Client,
    config: &FirewallConfig,
) -> Result<Vec<NewFirewallEvent>, String> {
    // 500 entries per cycle = ~100 events/min sustained, more than
    // enough for a /24 LAN. Operators with heavier traffic can raise
    // via env later if it ever matters.
    let body = opn_get_json(client, config, "/api/diagnostics/firewall/log?limit=500").await?;
    let arr = body.as_array().cloned().unwrap_or_default();
    let mut events = Vec::with_capacity(arr.len());
    for entry in arr {
        // OPNsense emits naive ISO ("2026-04-26T16:26:24") in server-local
        // time, no offset. Try strict RFC 3339 first (covers anyone
        // patching the API to send Z), fall back to NaiveDateTime
        // assuming UTC. We accept that operators on a non-UTC firewall
        // see timestamps slightly off — fixable later by reading the
        // system timezone from /api/diagnostics/system/system_information.
        let raw = entry.get("__timestamp__").and_then(|v| v.as_str());
        let timestamp = match raw {
            Some(s) => {
                if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s) {
                    d.with_timezone(&chrono::Utc)
                } else if let Ok(naive) =
                    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                {
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
                } else {
                    // Unparseable — skip rather than poison the batch.
                    continue;
                }
            }
            None => continue,
        };
        let action = entry
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let s = |k: &str| -> Option<String> {
            entry.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
        };
        let port_i32 = |k: &str| -> Option<i32> {
            entry
                .get(k)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&n| (1..=65535).contains(&n))
        };
        events.push(NewFirewallEvent {
            timestamp,
            fw_source: "opnsense".into(),
            interface: s("interface"),
            action,
            direction: s("dir"),
            proto: s("protoname"),
            src_ip: s("src"),
            src_port: port_i32("srcport"),
            dst_ip: s("dst"),
            dst_port: port_i32("dstport"),
            rule_id: s("rid").or_else(|| s("rulenr")),
            raw_meta: entry,
        });
    }
    Ok(events)
}

/// Active connections snapshot — pf_states.current is just a number.
async fn fetch_pf_states_count(client: &Client, config: &FirewallConfig) -> Result<i64, String> {
    let body = opn_get_json(client, config, "/api/diagnostics/firewall/pf_states").await?;
    Ok(body
        .get("current")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0))
}

#[derive(Debug, Clone, Deserialize)]
struct OpenvpnSession {
    common_name: Option<String>,
    real_address: Option<String>,
}

async fn fetch_openvpn_sessions(
    client: &Client,
    config: &FirewallConfig,
) -> Result<Vec<OpenvpnSession>, String> {
    let body = opn_get_json(client, config, "/api/openvpn/service/searchSessions").await?;
    let rows = body
        .get("rows")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));
    serde_json::from_value::<Vec<OpenvpnSession>>(rows)
        .map_err(|e| format!("openvpn deserialize: {}", e))
}

/// WireGuard returns a mixed list (interfaces + peers). We count peers
/// only; "active" = peer with a non-null latest-handshake-epoch within
/// the last 3 minutes (WG keepalive default is 25 s).
async fn fetch_wireguard_peers(
    client: &Client,
    config: &FirewallConfig,
) -> Result<(usize, usize), String> {
    let body = opn_get_json(client, config, "/api/wireguard/service/show").await?;
    let rows = body
        .get("rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut total = 0usize;
    let mut active = 0usize;
    let now = chrono::Utc::now().timestamp();
    for row in rows {
        if row.get("type").and_then(|v| v.as_str()) != Some("peer") {
            continue;
        }
        total += 1;
        if let Some(ts) = row
            .get("latest-handshake-epoch")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
        {
            if ts > 0 && (now - ts) < 180 {
                active += 1;
            }
        }
    }
    Ok((total, active))
}

async fn fetch_ipsec_phase1(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let body = opn_get_json(client, config, "/api/ipsec/sessions/searchPhase1").await?;
    Ok(body
        .get("rows")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0))
}

/// POST JSON to an OPNsense endpoint with basic auth.
async fn opn_post_json(
    client: &Client,
    config: &FirewallConfig,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", config.url, path);
    let resp = client
        .post(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .json(body)
        .send()
        .await
        .map_err(|e| format!("HTTP request error: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON parse error: {}", e))
}

/// Parse OPNsense naive ISO timestamp ("2026-04-27T11:49:23") as UTC.
fn parse_opn_ts(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|nt| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(nt, chrono::Utc))
}

/// C27: pull a /var/log/<scope>/ logfile via the JSON API. URL pattern is
/// `/api/diagnostics/log/core/<scope>` (POST). Returns (ingest_count, new
/// cursor). The cursor is the ISO timestamp of the highest row seen, so
/// the next cycle passes `validFrom = epoch(cursor)` and we never scan
/// the whole file again.
async fn ingest_log_scope(
    store: &dyn Database,
    client: &Client,
    config: &FirewallConfig,
    host: &str,
    scope: &str,
    cursor: Option<&str>,
) -> Result<(usize, Option<String>), String> {
    // First sync: only pull the last hour. Subsequent syncs: from cursor.
    let valid_from_epoch = match cursor.and_then(parse_opn_ts) {
        Some(dt) => dt.timestamp(),
        None => chrono::Utc::now().timestamp() - 3600,
    };
    let body = serde_json::json!({
        "current": 1,
        "rowCount": 1000,
        "searchPhrase": "",
        "severity": "",
        "validFrom": valid_from_epoch.to_string(),
    });
    let path = format!("/api/diagnostics/log/core/{}", scope);
    let resp = opn_post_json(client, config, &path, &body).await?;
    let rows = resp
        .get("rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return Ok((0, None));
    }
    let cursor_dt = cursor.and_then(parse_opn_ts);
    let mut count = 0usize;
    let mut newest: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut newest_iso: Option<String> = None;
    let tag = format!("opnsense.{}", scope);
    for row in rows {
        let raw_ts = match row.get("timestamp").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let ts = match parse_opn_ts(raw_ts) {
            Some(t) => t,
            None => continue,
        };
        if let Some(c) = cursor_dt {
            if ts <= c {
                continue;
            }
        }
        let iso = ts.to_rfc3339();
        if store.insert_log(&tag, host, &row, &iso).await.is_ok() {
            count += 1;
        }
        if newest.is_none_or(|n| ts > n) {
            newest = Some(ts);
            newest_iso = Some(raw_ts.to_string());
        }
    }
    Ok((count, newest_iso))
}

/// Gateway status: returns total + how many are offline.
async fn fetch_gateways(
    client: &Client,
    config: &FirewallConfig,
) -> Result<(usize, usize), String> {
    let body = opn_get_json(client, config, "/api/routes/gateway/status").await?;
    let items = body
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let total = items.len();
    let offline = items
        .iter()
        .filter(|g| {
            g.get("status_translated")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase())
                .map(|s| s.contains("offline") || s.contains("down"))
                .unwrap_or(false)
        })
        .count();
    Ok((total, offline))
}

async fn fetch_aliases_count(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let body = opn_get_json(client, config, "/api/firewall/alias/searchItem").await?;
    Ok(body
        .get("rows")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0))
}

/// System info: returns the OPNsense version banner.
async fn fetch_system_info(
    client: &Client,
    config: &FirewallConfig,
) -> Result<Option<String>, String> {
    let body = opn_get_json(client, config, "/api/diagnostics/system/system_information").await?;
    Ok(body
        .get("versions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_vlan_pfsense() {
        assert_eq!(extract_vlan_from_interface(Some("em1.10")), Some(10));
        assert_eq!(extract_vlan_from_interface(Some("igb0.20")), Some(20));
    }

    #[test]
    fn test_extract_vlan_opnsense() {
        assert_eq!(extract_vlan_from_interface(Some("vtnet1_vlan10")), Some(10));
        assert_eq!(extract_vlan_from_interface(Some("vtnet0_vlan30")), Some(30));
    }

    #[test]
    fn test_extract_vlan_no_vlan() {
        assert_eq!(extract_vlan_from_interface(Some("em0")), None);
        assert_eq!(extract_vlan_from_interface(Some("lan")), None);
        assert_eq!(extract_vlan_from_interface(None), None);
    }
}

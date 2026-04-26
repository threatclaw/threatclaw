//! Velociraptor DFIR connector — real gRPC over mTLS.
//!
//! # Wire protocol
//!
//! Velociraptor exposes its API as pure gRPC on TCP port 8001 (see
//! `api_connection_string` in the `config api_client` YAML). There is
//! no grpc-gateway / REST bridge on that port — every hit with
//! `application/json` returns HTTP 415. Talking to it therefore
//! requires a real gRPC client speaking HTTP/2 + protobuf, which is
//! exactly what `tonic` gives us.
//!
//! # Authentication
//!
//! Pure mTLS. The api_client YAML ships three PEM blobs:
//!   - `ca_certificate` — Velociraptor's internal CA, signs both the
//!     server cert and the client cert. Pinned as the only trust root.
//!   - `client_cert` — our identity. CN is the API user name.
//!   - `client_private_key` — the key matching the client cert.
//!
//! No bearer token, no `Grpc-Metadata-Username` header: the TLS
//! handshake is the authentication.
//!
//! # Hostname verification
//!
//! Velociraptor's default server cert carries `CN=VelociraptorServer`
//! (operators almost never reissue it with a real DNS name). tonic
//! defaults to verifying the SAN against the URL host, so we force
//! `.domain_name("VelociraptorServer")`. Combined with the pinned CA,
//! impersonation requires stealing the Velociraptor CA private key.

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use super::velociraptor_proto::api_client::ApiClient as VrApiClient;
use super::velociraptor_proto::{
    ArtifactCollectorArgs, ArtifactParameters, ArtifactSpec, Hunt as HuntMsg, ListHuntsRequest,
    SearchClientsRequest, VqlCollectorArgs, VqlEnv, VqlRequest, hunt::State as HuntState,
};

/// Connection config for a single Velociraptor server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelociraptorConfig {
    pub api_url: String,
    pub ca_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub username: String,
    #[serde(default)]
    pub cursor_last_hunt_completion: Option<String>,
    #[serde(default = "default_max_findings")]
    pub max_findings_per_cycle: u32,
    /// Optional second client certificate with `administrator` role for
    /// destructive HITL actions (quarantine, kill_process, isolate_host).
    /// The read-only sync user (investigator,api role) cannot execute
    /// EXECVE/FILESYSTEM_WRITE plugins, so a separate api_client with
    /// elevated privileges is required.
    #[serde(default)]
    pub admin_client_cert_pem: Option<String>,
    #[serde(default)]
    pub admin_client_key_pem: Option<String>,
}

fn default_max_findings() -> u32 {
    500
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VelociraptorSyncResult {
    pub clients_imported: usize,
    pub hunts_fetched: usize,
    pub findings_created: usize,
    pub insert_errors: usize,
    pub errors: Vec<String>,
    pub cursor: Option<String>,
}

/// Build an mTLS tonic channel to the Velociraptor API.
async fn build_channel(config: &VelociraptorConfig) -> Result<Channel, String> {
    let raw = config.api_url.trim();
    let uri = if raw.starts_with("https://") || raw.starts_with("http://") {
        raw.to_string()
    } else if let Some(rest) = raw.strip_prefix("grpc://") {
        format!("https://{rest}")
    } else if let Some(rest) = raw.strip_prefix("grpcs://") {
        format!("https://{rest}")
    } else {
        format!("https://{raw}")
    };

    let ca = Certificate::from_pem(config.ca_pem.as_bytes());
    let identity_pem = format!(
        "{}\n{}",
        config.client_cert_pem.trim(),
        config.client_key_pem.trim()
    );
    let identity = Identity::from_pem(identity_pem.as_bytes(), identity_pem.as_bytes());

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity)
        .domain_name("VelociraptorServer");

    Channel::from_shared(uri.clone())
        .map_err(|e| format!("invalid api_url '{uri}': {e}"))?
        .tls_config(tls)
        .map_err(|e| format!("tls config: {e}"))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))
}

pub async fn sync_velociraptor(
    store: &dyn Database,
    config: &VelociraptorConfig,
) -> VelociraptorSyncResult {
    let mut result = VelociraptorSyncResult {
        cursor: config.cursor_last_hunt_completion.clone(),
        ..Default::default()
    };

    let channel = match build_channel(config).await {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("channel: {e}"));
            tracing::warn!("VELOCIRAPTOR: channel build failed: {e}");
            return result;
        }
    };

    let mut api = VrApiClient::new(channel);

    match fetch_clients(&mut api).await {
        Ok(clients) => {
            for c in &clients {
                import_client_as_asset(store, c).await;
                result.clients_imported += 1;
            }
        }
        Err(e) => result.errors.push(format!("list_clients: {e}")),
    }

    match fetch_hunts(&mut api).await {
        Ok(hunts) => {
            let cursor = config.cursor_last_hunt_completion.as_deref();
            let newer: Vec<_> = hunts
                .into_iter()
                .filter(|h| match cursor {
                    Some(cur) => h.completion_ts_rfc3339.as_deref().is_some_and(|t| t > cur),
                    None => true,
                })
                .take(config.max_findings_per_cycle as usize)
                .collect();

            result.hunts_fetched = newer.len();

            let mut newest_seen = cursor.map(String::from);
            for hunt in &newer {
                if let Some(ref ts) = hunt.completion_ts_rfc3339 {
                    if newest_seen
                        .as_deref()
                        .map(|c| ts.as_str() > c)
                        .unwrap_or(true)
                    {
                        newest_seen = Some(ts.clone());
                    }
                }
                if import_hunt_finding(store, hunt).await {
                    result.findings_created += 1;
                } else {
                    result.insert_errors += 1;
                }
            }

            if newest_seen != result.cursor {
                result.cursor = newest_seen;
            }
        }
        Err(e) => result.errors.push(format!("list_hunts: {e}")),
    }

    tracing::info!(
        "VELOCIRAPTOR SYNC: clients_imported={} hunts_fetched={} findings_created={} errors={}",
        result.clients_imported,
        result.hunts_fetched,
        result.findings_created,
        result.errors.len()
    );

    result
}

#[derive(Debug, Clone)]
struct ClientSummary {
    client_id: String,
    hostname: String,
    fqdn: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
    mac_addresses: Vec<String>,
    last_ip: Option<String>,
    last_seen_at_ms: Option<i64>,
}

async fn fetch_clients(api: &mut VrApiClient<Channel>) -> Result<Vec<ClientSummary>, String> {
    let req = SearchClientsRequest {
        query: "all".into(),
        limit: 2000,
        ..Default::default()
    };
    let resp = api
        .list_clients(req)
        .await
        .map_err(status_to_str)?
        .into_inner();

    let mut out = Vec::with_capacity(resp.items.len());
    for c in resp.items {
        if c.client_id.is_empty() {
            continue;
        }
        let os = c.os_info.unwrap_or_default();
        out.push(ClientSummary {
            client_id: c.client_id,
            hostname: os.hostname,
            fqdn: if os.fqdn.is_empty() {
                None
            } else {
                Some(os.fqdn)
            },
            os_name: if os.system.is_empty() {
                None
            } else {
                Some(os.system)
            },
            os_version: if os.release.is_empty() {
                None
            } else {
                Some(os.release)
            },
            mac_addresses: os.mac_addresses,
            last_ip: if c.last_ip.is_empty() {
                None
            } else {
                Some(c.last_ip)
            },
            last_seen_at_ms: Some((c.last_seen_at / 1000) as i64),
        });
    }
    Ok(out)
}

async fn import_client_as_asset(store: &dyn Database, c: &ClientSummary) {
    let os = match (&c.os_name, &c.os_version) {
        (Some(n), Some(v)) if !v.is_empty() => Some(format!("{n} {v}")),
        (Some(n), _) => Some(n.clone()),
        _ => None,
    };

    let primary_mac = c
        .mac_addresses
        .iter()
        .find(|m| !m.is_empty() && *m != "00:00:00:00:00:00")
        .cloned();

    let discovered = DiscoveredAsset {
        mac: primary_mac,
        hostname: if c.hostname.is_empty() {
            None
        } else {
            Some(c.hostname.clone())
        },
        fqdn: c.fqdn.clone(),
        ip: c.last_ip.clone(),
        os,
        ports: None,
        services: serde_json::json!([]),
        ou: None,
        vlan: None,
        vm_id: None,
        criticality: Some("medium".into()),
        source: "velociraptor".into(),
    };
    let _ = asset_resolution::resolve_asset(store, &discovered).await;
}

#[derive(Debug, Clone)]
struct HuntSummary {
    hunt_id: String,
    hunt_description: String,
    artifacts: Vec<String>,
    clients_with_results: i64,
    creator: String,
    completion_ts_rfc3339: Option<String>,
}

async fn fetch_hunts(api: &mut VrApiClient<Channel>) -> Result<Vec<HuntSummary>, String> {
    let req = ListHuntsRequest {
        offset: 0,
        count: 500,
        include_archived: false,
        ..Default::default()
    };
    let resp = api
        .list_hunts(req)
        .await
        .map_err(status_to_str)?
        .into_inner();

    let mut out = Vec::with_capacity(resp.items.len());
    for h in resp.items {
        if h.hunt_id.is_empty() {
            continue;
        }
        if h.state != HuntState::Stopped as i32 {
            continue;
        }
        out.push(hunt_to_summary(h));
    }
    Ok(out)
}

fn hunt_to_summary(h: HuntMsg) -> HuntSummary {
    let completion_us = h
        .stats
        .as_ref()
        .map(|s| s.stopped as i64)
        .filter(|v| *v > 0)
        .unwrap_or(h.create_time as i64);
    let completion_ts_rfc3339 = us_to_rfc3339(completion_us);

    let artifacts = h
        .start_request
        .as_ref()
        .map(|s: &ArtifactCollectorArgs| s.artifacts.clone())
        .filter(|a| !a.is_empty())
        .unwrap_or(h.artifacts);

    let clients_with_results = h
        .stats
        .as_ref()
        .map(|s| s.total_clients_with_results as i64)
        .unwrap_or(0);

    HuntSummary {
        hunt_id: h.hunt_id,
        hunt_description: h.hunt_description,
        artifacts,
        clients_with_results,
        creator: h.creator,
        completion_ts_rfc3339,
    }
}

fn us_to_rfc3339(us: i64) -> Option<String> {
    let secs = match us {
        n if n < 1_000_000_000_000 => n,
        n if n < 1_000_000_000_000_000 => n / 1_000,
        n if n < 1_000_000_000_000_000_000 => n / 1_000_000,
        n => n / 1_000_000_000,
    };
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
}

async fn import_hunt_finding(store: &dyn Database, h: &HuntSummary) -> bool {
    let severity = if h.clients_with_results > 0 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let title = format!(
        "[Velociraptor hunt] {} — {} clients",
        if h.hunt_description.is_empty() {
            &h.hunt_id
        } else {
            &h.hunt_description
        },
        h.clients_with_results
    );

    let description = format!(
        "Hunt: {}\nArtifacts: {}\nClients with results: {}\nCreator: {}",
        h.hunt_id,
        h.artifacts.join(", "),
        h.clients_with_results,
        h.creator
    );

    crate::connectors::log_db_write(
        "velociraptor:hunt_finding",
        store.insert_finding(&NewFinding {
            skill_id: "skill-velociraptor".into(),
            title,
            description: Some(description),
            severity: severity.into(),
            category: Some("dfir-hunt".into()),
            asset: None,
            source: Some("Velociraptor".into()),
            metadata: Some(serde_json::json!({
                "hunt_id": h.hunt_id,
                "artifacts": h.artifacts,
                "clients_with_results": h.clients_with_results,
            })),
        }),
    )
    .await
    .is_some()
}

async fn load_config(store: &dyn Database) -> Result<VelociraptorConfig, String> {
    let rows = store
        .get_skill_config("skill-velociraptor")
        .await
        .map_err(|e| format!("config read failed: {e}"))?;
    let map: std::collections::HashMap<String, String> =
        rows.into_iter().map(|r| (r.key, r.value)).collect();

    let require = |k: &str| -> Result<String, String> {
        map.get(k)
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| format!("skill-velociraptor: '{k}' not configured"))
    };

    Ok(VelociraptorConfig {
        api_url: require("api_url")?,
        ca_pem: require("ca_pem")?,
        client_cert_pem: require("client_cert_pem")?,
        client_key_pem: require("client_key_pem")?,
        username: require("username")?,
        cursor_last_hunt_completion: map.get("cursor_last_hunt_completion").cloned(),
        max_findings_per_cycle: map
            .get("max_findings_per_cycle")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500),
        admin_client_cert_pem: map
            .get("admin_client_cert_pem")
            .filter(|v| !v.is_empty())
            .cloned(),
        admin_client_key_pem: map
            .get("admin_client_key_pem")
            .filter(|v| !v.is_empty())
            .cloned(),
    })
}

/// Build an mTLS channel using the **admin** identity for destructive
/// actions. Errors clearly when the operator hasn't configured the
/// elevated api_client — the dashboard surfaces this back to the user
/// instead of trying with the read-only cert and silently failing
/// server-side.
async fn build_admin_channel(config: &VelociraptorConfig) -> Result<Channel, String> {
    let admin_cert = config
        .admin_client_cert_pem
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or(
            "skill-velociraptor: admin_client_cert_pem non configuré — \
             régénère un threatclaw.config.yaml avec --role administrator \
             et colle les blocs admin dans le panneau HITL",
        )?;
    let admin_key = config
        .admin_client_key_pem
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or("skill-velociraptor: admin_client_key_pem non configuré")?;

    let raw = config.api_url.trim();
    let uri = if raw.starts_with("https://") || raw.starts_with("http://") {
        raw.to_string()
    } else if let Some(rest) = raw.strip_prefix("grpc://") {
        format!("https://{rest}")
    } else if let Some(rest) = raw.strip_prefix("grpcs://") {
        format!("https://{rest}")
    } else {
        format!("https://{raw}")
    };

    let ca = Certificate::from_pem(config.ca_pem.as_bytes());
    let identity_pem = format!("{}\n{}", admin_cert.trim(), admin_key.trim());
    let identity = Identity::from_pem(identity_pem.as_bytes(), identity_pem.as_bytes());

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity)
        .domain_name("VelociraptorServer");

    Channel::from_shared(uri.clone())
        .map_err(|e| format!("invalid api_url '{uri}': {e}"))?
        .tls_config(tls)
        .map_err(|e| format!("tls config: {e}"))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))
}

/// Schedule a Velociraptor artifact collection on `client_id` using the
/// admin identity. `params` becomes the artifact's `env` block.
///
/// Returns the flow id assigned by the Velociraptor server. The flow
/// runs asynchronously on the endpoint; the operator can follow it in
/// the GUI under Flows.
async fn collect_admin_artifact(
    config: &VelociraptorConfig,
    client_id: &str,
    artifact: &str,
    params: &[(&str, String)],
) -> Result<String, String> {
    if !client_id.starts_with("C.") || client_id.len() < 4 {
        return Err(format!(
            "invalid client_id '{client_id}' (expected 'C.' + 16 hex)"
        ));
    }
    if artifact.is_empty() || artifact.contains(';') || artifact.contains('\n') {
        return Err(format!("invalid artifact '{artifact}'"));
    }
    let channel = build_admin_channel(config).await?;
    let mut api = VrApiClient::new(channel);

    let env = params
        .iter()
        .map(|(k, v)| VqlEnv {
            key: (*k).to_string(),
            value: v.clone(),
            comment: String::new(),
        })
        .collect::<Vec<_>>();

    let req = ArtifactCollectorArgs {
        client_id: client_id.to_string(),
        specs: vec![ArtifactSpec {
            artifact: artifact.to_string(),
            parameters: Some(ArtifactParameters { env }),
            ..Default::default()
        }],
        urgent: true,
        ..Default::default()
    };
    let resp = api
        .collect_artifact(req)
        .await
        .map_err(status_to_str)?
        .into_inner();
    Ok(resp.flow_id)
}

/// Quarantine an endpoint — adds host-firewall rules that block all
/// network traffic except to the Velociraptor frontend, so the agent
/// stays controllable while malware loses C2 / lateral movement.
///
/// Backed by the standard `Windows.Remediation.Quarantine` artifact
/// (Linux equivalent on Linux clients). Reversible via the Velociraptor
/// GUI flow "RemoveQuarantine".
pub async fn quarantine_endpoint(
    store: &dyn Database,
    client_id: &str,
) -> Result<serde_json::Value, String> {
    let config = load_config(store).await?;
    let flow_id =
        collect_admin_artifact(&config, client_id, "Windows.Remediation.Quarantine", &[]).await?;
    tracing::info!(
        "VELOCIRAPTOR: quarantine_endpoint scheduled flow={} client={}",
        flow_id,
        client_id
    );
    Ok(serde_json::json!({
        "flow_id": flow_id,
        "client_id": client_id,
        "artifact": "Windows.Remediation.Quarantine",
        "reversible": true,
        "undo_info": "RemoveQuarantine artifact via Velociraptor GUI",
    }))
}

/// Kill a process on the endpoint by name (or PID if numeric). Backed
/// by `Windows.Remediation.ProcessKill`. The agent runs taskkill / kill
/// server-side under the admin role; investigator-role api_clients will
/// be refused by Velociraptor itself.
pub async fn kill_process(
    store: &dyn Database,
    client_id: &str,
    process_name_or_pid: &str,
) -> Result<serde_json::Value, String> {
    let config = load_config(store).await?;
    // Velociraptor's ProcessKill takes ProcessName (substring match) or
    // ProcessId (exact). We send whichever matches the input shape so
    // the operator can pass either "evil.exe" or "4242".
    let params: Vec<(&str, String)> = if process_name_or_pid.chars().all(|c| c.is_ascii_digit()) {
        vec![("ProcessId", process_name_or_pid.to_string())]
    } else {
        vec![("ProcessName", process_name_or_pid.to_string())]
    };
    let flow_id = collect_admin_artifact(
        &config,
        client_id,
        "ThreatClaw.Remediation.ProcessKill",
        &params,
    )
    .await?;
    tracing::info!(
        "VELOCIRAPTOR: kill_process scheduled flow={} client={} target={}",
        flow_id,
        client_id,
        process_name_or_pid
    );
    Ok(serde_json::json!({
        "flow_id": flow_id,
        "client_id": client_id,
        "target": process_name_or_pid,
        "artifact": "ThreatClaw.Remediation.ProcessKill",
        "reversible": false,
    }))
}

/// Block all outbound connections from the endpoint except the
/// Velociraptor frontend. Same artifact as `quarantine_endpoint` but
/// surfaced as a separate action in the UI for operators who think of
/// it differently (full quarantine vs. egress block).
pub async fn isolate_host(
    store: &dyn Database,
    client_id: &str,
) -> Result<serde_json::Value, String> {
    let config = load_config(store).await?;
    let flow_id =
        collect_admin_artifact(&config, client_id, "Windows.Remediation.Quarantine", &[]).await?;
    tracing::info!(
        "VELOCIRAPTOR: isolate_host scheduled flow={} client={}",
        flow_id,
        client_id
    );
    Ok(serde_json::json!({
        "flow_id": flow_id,
        "client_id": client_id,
        "artifact": "Windows.Remediation.Quarantine",
        "reversible": true,
        "undo_info": "RemoveQuarantine artifact via Velociraptor GUI",
    }))
}

pub async fn tool_list_clients(store: &dyn Database) -> Result<serde_json::Value, String> {
    let config = load_config(store).await?;
    let channel = build_channel(&config).await?;
    let mut api = VrApiClient::new(channel);
    let clients = fetch_clients(&mut api).await?;
    Ok(serde_json::json!({
        "count": clients.len(),
        "clients": clients.iter().map(|c| serde_json::json!({
            "client_id": c.client_id,
            "hostname": c.hostname,
            "fqdn": c.fqdn,
            "os": match (&c.os_name, &c.os_version) {
                (Some(n), Some(v)) => format!("{n} {v}"),
                (Some(n), _) => n.clone(),
                _ => "".to_string(),
            },
            "last_ip": c.last_ip,
            "last_seen_ms": c.last_seen_at_ms,
        })).collect::<Vec<_>>(),
    }))
}

pub async fn tool_query(store: &dyn Database, vql: &str) -> Result<serde_json::Value, String> {
    validate_vql_readonly(vql)?;
    let config = load_config(store).await?;
    let channel = build_channel(&config).await?;
    let mut api = VrApiClient::new(channel);

    let args = VqlCollectorArgs {
        max_row: 500,
        max_wait: 15,
        query: vec![VqlRequest {
            name: "threatclaw-l2".into(),
            vql: vql.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut stream = api.query(args).await.map_err(status_to_str)?.into_inner();

    let mut rows = Vec::new();
    while let Some(msg) = stream.message().await.map_err(status_to_str)? {
        if !msg.jsonl_response.is_empty() {
            for line in msg.jsonl_response.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    rows.push(v);
                }
            }
        } else if !msg.response.is_empty() {
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(&msg.response) {
                rows.extend(arr);
            }
        }
    }

    Ok(serde_json::json!({
        "row_count": rows.len(),
        "rows": rows,
    }))
}

pub async fn tool_hunt(
    store: &dyn Database,
    description: &str,
    artifacts: &[String],
) -> Result<serde_json::Value, String> {
    if artifacts.is_empty() {
        return Err("hunt: at least one artifact required".into());
    }
    for a in artifacts {
        if a.is_empty() || a.contains(';') || a.contains('\n') {
            return Err(format!("hunt: invalid artifact name '{a}'"));
        }
    }
    let config = load_config(store).await?;
    let channel = build_channel(&config).await?;
    let mut api = VrApiClient::new(channel);

    let hunt = HuntMsg {
        hunt_description: description.to_string(),
        start_request: Some(ArtifactCollectorArgs {
            artifacts: artifacts.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let resp = api
        .create_hunt(hunt)
        .await
        .map_err(status_to_str)?
        .into_inner();
    Ok(serde_json::json!({
        "hunt_id": resp.flow_id,
        "status": "created",
        "description": description,
        "artifacts": artifacts,
    }))
}

pub async fn tool_collect(
    store: &dyn Database,
    client_id: &str,
    artifact: &str,
) -> Result<serde_json::Value, String> {
    if !client_id.starts_with("C.") || client_id.len() < 4 {
        return Err(format!(
            "collect: invalid client_id '{client_id}' (expected 'C.' + 16 hex)"
        ));
    }
    if artifact.is_empty() || artifact.contains(';') || artifact.contains('\n') {
        return Err(format!("collect: invalid artifact '{artifact}'"));
    }
    let config = load_config(store).await?;
    let channel = build_channel(&config).await?;
    let mut api = VrApiClient::new(channel);

    let req = ArtifactCollectorArgs {
        client_id: client_id.to_string(),
        artifacts: vec![artifact.to_string()],
        ..Default::default()
    };
    let resp = api
        .collect_artifact(req)
        .await
        .map_err(status_to_str)?
        .into_inner();
    Ok(serde_json::json!({
        "flow_id": resp.flow_id,
        "client_id": client_id,
        "artifact": artifact,
        "status": "scheduled",
    }))
}

pub fn validate_vql_readonly(vql: &str) -> Result<(), String> {
    let lower = vql.to_lowercase();
    for forbidden in [
        "execve(",
        "powershell(",
        "cmd(",
        "copy(",
        "upload_file(",
        "rm(",
        "mv(",
        "write_file(",
        "append_file(",
        "create_flow(",
        "delete_flow(",
        "reboot(",
        "shutdown(",
    ] {
        if lower.contains(forbidden) {
            return Err(format!("vql blocked: forbidden plugin '{forbidden}'"));
        }
    }
    Ok(())
}

fn status_to_str<S: Into<tonic::Status>>(s: S) -> String {
    let st: tonic::Status = s.into();
    format!("gRPC {:?}: {}", st.code(), st.message())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_vql_allows_read_queries() {
        assert!(validate_vql_readonly("SELECT * FROM clients()").is_ok());
        assert!(validate_vql_readonly("SELECT Fqdn FROM info() WHERE Hostname =~ 'foo'").is_ok());
        assert!(validate_vql_readonly("SELECT copy_count FROM x").is_ok());
    }

    #[test]
    fn validate_vql_blocks_writes_and_execve() {
        assert!(validate_vql_readonly("SELECT * FROM execve(argv=['whoami'])").is_err());
        assert!(validate_vql_readonly("SELECT * FROM powershell(command='ls')").is_err());
        assert!(validate_vql_readonly("SELECT create_flow(client_id='C.0')").is_err());
        assert!(validate_vql_readonly("SELECT write_file(path='/etc/hosts')").is_err());
    }

    #[test]
    fn us_to_rfc3339_handles_mixed_units() {
        assert!(us_to_rfc3339(1_735_689_600).unwrap().starts_with("2025"));
        assert!(
            us_to_rfc3339(1_735_689_600_000)
                .unwrap()
                .starts_with("2025")
        );
        assert!(
            us_to_rfc3339(1_735_689_600_000_000)
                .unwrap()
                .starts_with("2025")
        );
        assert!(
            us_to_rfc3339(1_735_689_600_000_000_000)
                .unwrap()
                .starts_with("2025")
        );
    }
}
